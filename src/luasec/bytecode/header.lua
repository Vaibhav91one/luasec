-- Parse the header of a precompiled Lua chunk, defensively.
--
-- This module is public (see AGENTS.md): header facts are useful on their own
-- to a firmware scanner, and it is the only place that knows the on-disk
-- layout. It reads fixed width scalars and nothing else, so a hostile file
-- cannot make it allocate, and it never raises -- a chunk it cannot describe
-- comes back as nil plus a reason.
--
-- Layouts, from lundump.c in each release:
--
--   5.1   ESC "Lua" ver fmt endian sizeof(int) sizeof(size_t)
--         sizeof(Instruction) sizeof(lua_Number) is_integral
--   5.2   the 5.1 shape plus the 6 byte LUAC_TAIL
--   5.3   ESC "Lua" ver fmt LUAC_DATA
--         sizeof(int) sizeof(size_t) sizeof(Instruction)
--         sizeof(lua_Integer) sizeof(lua_Number) LUAC_INT LUAC_NUM
--   5.4   ESC "Lua" ver fmt LUAC_DATA
--         sizeof(Instruction) sizeof(lua_Integer) sizeof(lua_Number)
--         LUAC_INT LUAC_NUM
--
-- 5.1 and 5.2 have no LUAC_DATA and no numeric markers: they record an
-- explicit endianness byte instead. 5.3 and 5.4 check LUAC_INT (0x5678) and
-- LUAC_NUM (370.5), which is how a byte swapped chunk gets caught.
local detect = require "luasec.bytecode.detect"

local header = {}

header.LUAC_DATA = "\x19\x93\r\n\x1a\n"
header.LUAC_INT = 0x5678
header.LUAC_NUM = 370.5

-- What we assume is running the code we analyze. A chunk that does not match
-- gets 803, because its layout may be one we cannot reason about.
header.ASSUMED_FLAVOR = "lua"
header.ASSUMED_VERSION = "5.4"

local PUC_51, PUC_52, PUC_53, PUC_54 = 0x51, 0x52, 0x53, 0x54

-- Which reader handles which PUC version byte, and under what name it parses.
-- Populated below, once both readers exist; `header.parse` only looks at it at
-- call time.
local PUC_READERS

-- A failure is (nil, reason). Reasons are short and safe to show in a report.
local function fail(reason)
   return nil, reason
end

-- One byte at a time, accumulating into a widths table. Returns the widths and
-- the next position, or nil plus a reason. Written as a loop rather than a
-- sequence of assignments so the position is threaded in one place.
local function read_widths(bytes, pos, keys)
   local widths = {}
   for _, key in ipairs(keys) do
      widths[key], pos = header.read_byte(bytes, pos, "sizeof(" .. key .. ")")
      if not widths[key] then return nil, pos end
   end
   return widths, pos
end

--- Parse the header of `bytes`.
--
-- On success returns a table:
--   flavor, version, version_byte, format
--   sizes    the widths the chunk claims, as recorded
--   luac_data, luac_int, luac_number   the markers, as read
--   endian   "little" or "big"
--   end_offset   index of the first byte after the header
--
-- On failure returns nil plus a reason.
function header.parse(bytes, id)
   if type(bytes) ~= "string" then return fail("not a byte string") end

   id = id or detect.identify(bytes)
   if not id then return fail("not a Lua bytecode signature") end

   if id.flavor == "luajit" then
      return header.parse_luajit(bytes, id)
   end

   -- Deliberately total: there is no fallback branch, and no "assume the
   -- newest" default. A version byte with no reader here is a chunk whose
   -- layout we cannot justify, and guessing would be worse than refusing,
   -- because the version byte is the only statement the file makes about its
   -- own encoding. The prototype walk reads the file with `parsed.version`, so
   -- a guess made here turns into a confident walk of a layout the file never
   -- claimed, and into findings drawn from it.
   local reader = PUC_READERS[id.version_byte]
   if not reader then
      return fail(string.format("no header reader for PUC version byte 0x%02X",
         id.version_byte))
   end
   return reader.read(bytes, id, reader.version)
end

-- ------------------------------------------------------------- 5.1 and 5.2

-- Same field order; 5.2 appends the 6 byte LUAC_TAIL.
function header.parse_legacy(bytes, id, version)
   local pos = 6  -- ESC "Lua" and the version byte
   local format, pos = header.read_byte(bytes, pos, "the format byte")
   if not format then return nil, pos end

   local endian_byte, pos = header.read_byte(bytes, pos, "the endianness byte")
   if not endian_byte then return nil, pos end
   -- luaU_header stores the first byte of int 1, which is 1 little endian.
   if endian_byte ~= 0 and endian_byte ~= 1 then
      return fail(string.format("endianness byte is 0x%02X, expected 0 or 1", endian_byte))
   end
   local endian = endian_byte == 1 and "little" or "big"

   local sizes, pos = read_widths(bytes, pos,
      {"int", "size_t", "instruction", "lua_Number"})
   if not sizes then return nil, pos end

   -- luaU_header also records whether lua_Number is integral, which is how a
   -- 32 bit integer build is told from a float one. We only support the
   -- floating forms, so anything else is refused here rather than misread.
   local integral
   integral, pos = header.read_byte(bytes, pos, "the lua_Number kind byte")
   if not integral then return nil, pos end
   if integral ~= 0 then
      return fail("lua_Number is integral; this build only reads floating point chunks")
   end

   if version == "5.2" then
      if bytes:sub(pos, pos + #header.LUAC_DATA - 1) ~= header.LUAC_DATA then
         return fail("LUAC_TAIL mismatch")
      end
      pos = pos + #header.LUAC_DATA
   end

   return {
      flavor = "lua",
      version = version,
      version_byte = id.version_byte,
      format = format,
      sizes = sizes,
      luac_data = version == "5.2" and header.LUAC_DATA or nil,
      luac_int = nil,
      luac_number = nil,
      endian = endian,
      end_offset = pos - 1,
   }
end

-- ------------------------------------------------------------- 5.3 and 5.4

-- 5.3 and 5.4 share a header layout and differ only in which widths they
-- record: 5.3 still writes sizeof(int) and sizeof(size_t), which the prototype
-- reader needs, and 5.4 dropped them.
local MARKER_WIDTHS = {
   ["5.3"] = {"int", "size_t", "instruction", "lua_Integer", "lua_Number"},
   ["5.4"] = {"instruction", "lua_Integer", "lua_Number"},
}

function header.parse_marked(bytes, id, version)
   local pos = 6  -- ESC "Lua" and the version byte
   local format, pos = header.read_byte(bytes, pos, "the format byte")
   if not format then return nil, pos end

   if bytes:sub(pos, pos + #header.LUAC_DATA - 1) ~= header.LUAC_DATA then
      return fail("LUAC_DATA marker mismatch")
   end
   pos = pos + #header.LUAC_DATA

   local sizes, pos = read_widths(bytes, pos, MARKER_WIDTHS[version])
   if not sizes then return nil, pos end

   local endian = "little"
   local marker, pos = header.read_integer(bytes, pos, sizes.lua_Integer, endian, "LUAC_INT")
   if not marker then return nil, pos end

   local number, pos = header.read_double(bytes, pos, sizes.lua_Number, endian)
   if not number then return nil, pos end

   local reason = header.check_markers(marker, number, endian)
   if reason then return fail(reason) end

   return {
      flavor = "lua",
      version = version,
      version_byte = id.version_byte,
      format = format,
      sizes = sizes,
      luac_data = header.LUAC_DATA,
      luac_int = marker,
      luac_number = number,
      endian = endian,
      end_offset = pos - 1,
   }
end

-- The version byte is the file's only statement about its own encoding, so
-- dispatch is total: every byte we are willing to name, mapped to the reader
-- that understands it. A byte missing from this table is a chunk we refuse,
-- never one we read as the nearest neighbour.
PUC_READERS = {
   [PUC_51] = {version = "5.1", read = header.parse_legacy},
   [PUC_52] = {version = "5.2", read = header.parse_legacy},
   [PUC_53] = {version = "5.3", read = header.parse_marked},
   [PUC_54] = {version = "5.4", read = header.parse_marked},
}

-- A chunk is only what it claims when both markers survived. A byte swapped
-- LUAC_INT is the common case (a big endian producer, or a file that was
-- shuffled), so it gets its own message rather than "corrupt".
--
-- The marker is read from up to eight bytes, so it can be a value Lua has no
-- exact integer for. Messages therefore go through tostring rather than %X:
-- formatting such a value with %X raises, and this must not raise.
function header.check_markers(marker, number, endian)
   if marker ~= header.LUAC_INT then
      if endian == "little" and marker == header.REVERSED_LUAC_INT then
         return "LUAC_INT is byte reversed: the chunk is big endian"
      end
      return string.format("LUAC_INT is %s, expected 0x%X", tostring(marker), header.LUAC_INT)
   end
   if number ~= header.LUAC_NUM then
      return string.format("LUAC_NUM is %s, expected %s", tostring(number), tostring(header.LUAC_NUM))
   end
   return nil
end

-- ------------------------------------------------------------- LuaJIT

-- luajit -b writes ESC "LJ", a dump version byte, a flags byte, and, unless
-- the chunk was stripped, a chunk name. We stop there: the BC format after
-- that is a different, undocumented layout, and guessing at it is how a
-- scanner turns into a crash.
--
-- The flags byte is four independent bits (lj_bcdump.h), not a set of
-- enumerated modes, so each is tested where it sits rather than by matching the
-- whole byte:
--
--   BCDUMP_F_BE    0x01   the chunk is big endian
--   BCDUMP_F_STRIP 0x02   the debug information has been stripped
--   BCDUMP_F_FFI   0x04   the chunk uses the FFI
--   BCDUMP_F_FR2   0x08   frame 2 of the bytecode, the 5.2+ compatible form
function header.parse_luajit(bytes, id)
   local pos = 4  -- ESC "LJ" consumed
   local version_byte, pos = header.read_byte(bytes, pos, "the LuaJIT version byte")
   if not version_byte then return nil, pos end
   local flags, pos = header.read_byte(bytes, pos, "the LuaJIT flags byte")
   if not flags then return nil, pos end

   local BCDUMP_F_BE, BCDUMP_F_STRIP = 0x01, 0x02

   -- One named bit of the flags byte. Arithmetic rather than a bitwise `&`,
   -- which is 5.3 and later only, so the reader does not tie this module to a
   -- Lua version while it is busy identifying them.
   local function flag(bit)
      return math.floor(flags / bit) % 2 == 1
   end

   return {
      flavor = "luajit",
      version = id.version,
      version_byte = version_byte,
      format = flags,
      sizes = {},
      luac_data = nil,
      luac_int = nil,
      luac_number = nil,
      -- Both of these are read out of the byte rather than assumed. A fixed
      -- "little" would be a claim about the file that the flags byte directly
      -- contradicts, and reading BCDUMP_F_BE as the strip flag would be a
      -- second one: every big endian chunk would be called stripped.
      endian = flag(BCDUMP_F_BE) and "big" or "little",
      stripped = flag(BCDUMP_F_STRIP),
      end_offset = pos - 1,
   }
end

-- ------------------------------------------------------------- primitives

-- LUAC_INT as it looks when every byte is reversed, which is what a big endian
-- producer writes. The file holds 78 56 00 00 00 00 00 00 for a little endian
-- chunk and 00 00 00 00 00 00 56 78 for a big endian one, so a little endian
-- read of the latter is 0x7856000000000000.
header.REVERSED_LUAC_INT = 0x7856000000000000

function header.read_byte(bytes, pos, what)
   local byte = bytes:byte(pos)
   if byte == nil then return fail("truncated before " .. what) end
   return byte, pos + 1
end

--- Read `width` bytes at `pos` as an unsigned integer in the given byte order.
--
-- Widths outside 1..8 are refused rather than silently truncated, and a read
-- that would run past the end of the file is refused before any byte is taken.
-- The result can exceed the range Lua holds exactly; callers that print it must
-- use tostring, not %X.
function header.read_integer(bytes, pos, width, endian, what)
   what = what or "a field"
   if type(width) ~= "number" or width ~= math.floor(width)
      or width < 1 or width > 8
   then
      return fail(string.format("%s width %s is not a usable integer size", what, tostring(width)))
   end
   if pos + width - 1 > #bytes then
      return fail("truncated before " .. what)
   end

   local value = 0
   for i = 0, width - 1 do
      -- A little endian file stores the least significant byte first, so the
      -- i-th byte carries weight 2^(8i). A big endian file stores the bytes the
      -- other way round, hence the mirrored offset.
      local offset = endian == "big" and (width - 1 - i) or i
      value = value + bytes:byte(pos + offset) * 2 ^ (8 * i)
   end
   return value, pos + width
end

-- Lua numbers are doubles, or floats in a 32 bit build. Read whichever width the
-- header claims and nothing else: a width we do not recognize means we would be
-- misreading every constant in the chunk.
function header.read_double(bytes, pos, width, endian)
   if width ~= 8 and width ~= 4 then
      return fail(string.format("number width %s is neither 4 nor 8", tostring(width)))
   end
   if pos + width - 1 > #bytes then return fail("truncated before a number") end
   return header.read_ieee(bytes, pos, width, endian), pos + width
end

-- IEEE 754, decoded by hand rather than with string.unpack, so the answer
-- depends on nothing but the bytes and works whatever the host float format is.
--
--   normal     (-1)^sign * 1.fraction * 2^(exponent - bias)
--   subnormal  (-1)^sign * 0.fraction * 2^(1 - bias)
--   inf/NaN    an infinity, which can never equal a marker we compare against
--
--   double  sign 1, exponent 11, fraction 52   (1 + 11 + 52 = 64)
--   float   sign 1, exponent  8, fraction 23   (1 +  8 + 23 = 32)
function header.read_ieee(bytes, pos, width, endian)
   local exponent_bits, fraction_bits, bias, low_bytes
   if width == 8 then
      exponent_bits, fraction_bits, bias, low_bytes = 11, 52, 1023, 4
   else
      exponent_bits, fraction_bits, bias, low_bytes = 8, 23, 127, 0
   end

   -- How many of the fraction bits sit in the most significant 32 bits. A float
   -- is 32 bits wide, so all 23 of its fraction bits are there. A double keeps
   -- 32 of its 52 in the low word, leaving 20 in the high one. The exponent sits
   -- immediately above the fraction, so the same number is the exponent shift.
   local low_bits = low_bytes > 0 and 32 or 0
   local fraction_in_high = fraction_bits - low_bits

   -- The sign, the exponent and the top of the fraction live in the most
   -- significant 32 bits: the last four bytes of a little endian value, the
   -- first four of a big endian one.
   -- read_integer also returns the next position, so the value is taken on its
   -- own here rather than captured alongside it.
   local high_at = endian == "big" and pos or pos + low_bytes
   local high = header.read_integer(bytes, high_at, 4, endian, "a number")
   local low = 0
   if low_bytes > 0 then
      local low_at = endian == "big" and pos + 4 or pos
      low = header.read_integer(bytes, low_at, 4, endian, "a number")
   end

   local sign = (math.floor(high / 0x80000000) == 1) and -1 or 1
   local exponent = math.floor(high / 2 ^ fraction_in_high) % 2 ^ exponent_bits
   local fraction = (high % 2 ^ fraction_in_high) * (low_bytes > 0 and 2 ^ 32 or 1) + low

   if exponent == 0 then
      return sign * fraction * 2 ^ (1 - bias - fraction_bits)
   end
   if exponent == 2 ^ exponent_bits - 1 then
      return sign * math.huge
   end
   return sign * (2 ^ fraction_bits + fraction) * 2 ^ (exponent - bias - fraction_bits)
end

return header
