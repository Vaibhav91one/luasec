-- Regenerate the binary fixtures under test/fixtures/bytecode/.
--
--   build/lua-5.4.9/src/lua scripts/make-bytecode-fixtures.lua
--
-- The output is committed, so this script only has to run when a fixture
-- changes. It never analyses anything; it just writes bytes.
--
-- What each fixture is and where it comes from:
--
--   hello.luac        REAL. `build/lua-5.4.9/src/luac` compiling a two line
--                     Lua 5.4 source. The silent fixture: a well formed chunk
--                     that references no execution sink.
--   sink_exec.luac    REAL, same luac. Source holds the literal "os.execute"
--                     and reads the real os.execute table, so the constant
--                     table names a sink. Fires 802.
--   v51.luac          REAL, from a Lua 5.1.5 `luac` (see LUAC51 below). Same
--                     source shape as sink_exec, so it also fires 802. Proves
--                     a 5.1 chunk is 801, is not a parse error, and that the
--                     5.1 header and prototype layout are read correctly.
--   v52.luac, v53.luac REAL, from Lua 5.2.4 and 5.3.6 `luac`. They differ from
--                     5.1 in the header and in how strings, integers and line
--                     info are stored, so a parser that only understands 5.4
--                     will fail on them. They fire 803 (version mismatch) and
--                     802.
--   luajit.luac       HAND BUILT. The machine has no luajit. These are the
--                     first bytes luajit -b writes: "\27LJ", dump version 2,
--                     flags 0, then a chunk name. Proves the LuaJIT
--                     signature is recognized as its own flavor.
--   tiny.luac         HAND BUILT, 8 bytes: "\27Lua" + version + format + two
--                     bytes. A signature with nothing behind it.
--   truncated.luac    DERIVED: the first 20 bytes of hello.luac, which stops
--                     in the middle of the LUAC_INT / LUAC_NUM markers.
--   wrong_endian.luac DERIVED: hello.luac with all 8 bytes of the LUAC_INT
--                     marker reversed, so 0x5678 reads as 0x7856341200000000,
--                     which is what a big endian producer would write.
--   hostile_random.luac   "\27Lua" + 4092 pseudo random bytes. Exactly the
--                     "4 KB of noise behind a valid signature" case.
--   hostile_sizes.luac    Hand built 5.4 header plus a main prototype whose
--                     constant table claims one string of 0x3FFFFFFF bytes
--                     and no payload.
--   hostile_constants.luac Hand built 5.4 header plus a main prototype whose
--                     constant table claims 200001 constants (past the 100k
--                     read cap) with no payload.
--   hostile_depth.luac     Hand built 5.4 header plus 100 nested prototypes
--                     (past the depth cap of 64); the innermost one holds
--                     the string "os.execute" so the spec can prove the walk
--                     really stops at the cap.
--   unknown_version.luac DERIVED: sink_exec.luac with its version byte changed
--                     from 0x54 to 0x99. A real PUC signature, a version byte
--                     that names no release, and an "os.execute" sitting in
--                     the constants. Read as 5.4 it fires 802; the spec asserts
--                     it does not, because a layout we cannot justify must not
--                     produce a finding.
local OUT = "test/fixtures/bytecode"

-- The 5.4 toolchain ships with the repo. The 5.1, 5.2 and 5.3 ones do not, so
-- point these at your own builds to regenerate those fixtures:
--
--   LUAC=/path/to/luac LUAC51=... LUAC52=... LUAC53=... \
--      lua scripts/make-bytecode-fixtures.lua
--
-- The committed output does not change when the paths change: luac output is
-- deterministic for a given version and source.
local LUAC = os.getenv("LUAC") or "build/lua-5.4.9/src/luac"
local LUAC51 = os.getenv("LUAC51")
local LUAC52 = os.getenv("LUAC52")
local LUAC53 = os.getenv("LUAC53")

-- ------------------------------------------------------------ byte helpers

local function str(list)
   local parts = {}
   for i = 1, #list do parts[i] = string.char(list[i]) end
   return table.concat(parts)
end

-- Fixed width little endian, as a 5.1 dump stores ints and size_t.
local function le(value, width)
   local out = {}
   for i = 1, width do
      local shift = 8 * (i - 1)
      out[i] = math.floor(value / 2 ^ shift) % 256
   end
   return out
end

-- The 5.4 size encoding (ldump.c dumpSize, lundump.c loadUnsigned): 7 bit
-- groups, most significant first, with the high bit set on the last group to
-- mark the end of the run. So 0x80 is the value 0. Only 5.4 uses this; 5.1 to
-- 5.3 store integers and sizes as native words.
local function varint(value)
   local groups = {}
   repeat
      groups[#groups + 1] = value % 128
      value = math.floor(value / 128)
   until value == 0

   local out = {}
   for i = #groups, 1, -1 do out[#out + 1] = groups[i] end
   out[#out] = out[#out] + 128
   return out
end

-- 5.1 to 5.3 store a string as a native size_t length (which counts the
-- trailing NUL) followed by the bytes themselves. 5.3 reads that length as a
-- single byte unless it is 0xFF, which is why the width is passed in.
local function sized_native(text, width)
   local out = le(#text + 1, width)
   for i = 1, #text do out[#out + 1] = text:byte(i) end
   return out
end

-- 5.4 stores a string as a varint length (also counting the trailing NUL)
-- followed by the bytes.
local function sized(text)
   local out = varint(#text + 1)
   for i = 1, #text do out[#out + 1] = text:byte(i) end
   return out
end

-- ------------------------------------------------------------ real chunks

local function compile(luac, source_text, output)
   -- luac embeds the input path as the prototype's source name, so write the
   -- source to a path with a stable name rather than a random temp file: the
   -- committed fixtures then do not change on every run.
   local input = "test/fixtures/bytecode/.tmp-" .. output:gsub(".*/", ""):gsub("%.luac$", ".lua")
   local handle = assert(io.open(input, "w"))
   handle:write(source_text)
   handle:close()
   -- No -s: the debug information is what carries the source name, the line
   -- range and the upvalue names, and the whole point of these fixtures is to
   -- exercise the prototype walk.
   local status = os.execute(string.format("%q -o %q %q", luac, output, input))
   os.remove(input)
   assert(status == true or status == 0, "luac failed for " .. output)
end

-- Compile with the given toolchain when it is configured, otherwise leave the
-- committed fixture alone. Callers print what happened either way.
local function compile_optional(luac, source_text, output, label)
   if not luac then
      print(string.format("%-26s skipped (set %s to regenerate)", output, label))
      return false
   end
   compile(luac, source_text, output)
   return true
end

-- ------------------------------------------------------------ 5.4 header

-- The 5.4 header is 32 bytes: signature, version 0x54, format 0, LUAC_DATA,
-- sizeof Instruction / lua_Integer / lua_Number, then the two numeric markers.
local HEADER54 = {
   0x1B, 0x4C, 0x75, 0x61,                     -- "\27Lua"
   0x54,                                       -- LUAC_VERSION, 5.4
   0x00,                                       -- LUAC_FORMAT
   0x19, 0x93, 0x0D, 0x0A, 0x1A, 0x0A,         -- LUAC_DATA
   4, 8, 8,                                    -- sizeof Instruction, lua_Integer, lua_Number
}

local LUAC_INT_MARKER = le(0x5678, 8)
local LUAC_NUM_MARKER = {0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x77, 0x40}  -- 370.5

local function join(...)
   local out = {}
   for _, list in ipairs({...}) do
      for _, byte in ipairs(list) do out[#out + 1] = byte end
   end
   return str(out)
end

-- A 5.4 main prototype: no source name, no code, no constants, and empty
-- debug information, unless the caller overrides one of them. The field order
-- is loadFunction in lundump.c.
local function proto54(options)
   options = options or {}
   local out = {}
   local function add(list)
      for _, item in ipairs(list) do
         if type(item) == "table" then add(item) else out[#out + 1] = item end
      end
   end

   add(options.source and sized(options.source) or varint(0))
   add(varint(0))                       -- linedefined
   add(varint(0))                       -- lastlinedefined
   add({0, 1, 2})                       -- numparams, is_vararg, maxstacksize
   add(varint(0))                       -- sizecode
   add(varint(options.constants or 0))
   add(options.constant or {})
   add(varint(0))                       -- sizeupvalues
   add(varint(options.children or 0))
   add(options.children_body or {})
   add(varint(0))                       -- sizelineinfo
   add(varint(0))                       -- sizeabslineinfo
   add(varint(0))                       -- sizelocvars
   add(varint(0))                       -- upvalue names
   return out
end

-- The 5.1 header, from luaU_header in lundump.c. Note what is *not* here: 5.1
-- and 5.2 have no LUAC_DATA tail and no LUAC_INT / LUAC_NUM markers. They
-- record an endianness byte, sizeof(int) and sizeof(size_t) instead, and stop
-- at 12 and 18 bytes respectively.
local HEADER51 = {
   0x1B, 0x4C, 0x75, 0x61,  -- "\27Lua"
   0x51,                    -- LUAC_VERSION, 5.1
   0x00,                    -- LUAC_FORMAT
   0x01,                    -- endianness: first byte of int 1 on a little endian host
   4,                       -- sizeof(int)
   8,                       -- sizeof(size_t)
   4,                       -- sizeof(Instruction)
   8,                       -- sizeof(lua_Number)
   0x00,                    -- lua_Number is not integral
}

local HEADER52 = {
   0x1B, 0x4C, 0x75, 0x61,
   0x52,
   0x00,
   0x01,
   4, 8, 4, 8,
   0x00,
   0x19, 0x93, 0x0D, 0x0A, 0x1A, 0x0A,  -- LUAC_TAIL
}

-- ------------------------------------------------------------ writers

local function write(name, data)
   local path = OUT .. "/" .. name
   local handle = assert(io.open(path, "wb"))
   handle:write(data)
   handle:close()
   print(string.format("%-26s %6d bytes", name, #data))
end

assert(os.execute("mkdir -p " .. OUT) == true or os.execute("mkdir -p " .. OUT) == 0)

-- REAL: two lines of 5.4, no sink anywhere.
compile(LUAC, "local greeting = 'hi'\nreturn greeting\n", OUT .. "/hello.luac")

-- REAL: the literal names a sink and the table is read for real.
compile(LUAC, "local runner = 'os.execute'\nlocal f = os.execute\nreturn runner, f\n",
   OUT .. "/sink_exec.luac")

-- REAL, per version. Same source for all three so the fixtures differ only in
-- how their producer encodes a chunk: a source name in the debug block, a line
-- range, one _ENV upvalue and one constant naming a sink.
local SINK_SOURCE = "local function run(cmd)\n  return os.execute(cmd)\nend\nreturn run\n"
compile_optional(LUAC51, SINK_SOURCE, OUT .. "/v51.luac", "LUAC51")
compile_optional(LUAC52, SINK_SOURCE, OUT .. "/v52.luac", "LUAC52")
compile_optional(LUAC53, SINK_SOURCE, OUT .. "/v53.luac", "LUAC53")

-- REAL-shaped but hand written: there is no luajit on this machine.
write("luajit.luac", join({0x1B, 0x4C, 0x4A, 0x02, 0x00}, sized("@luajit.luac")))

write("tiny.luac", str({0x1B, 0x4C, 0x75, 0x61, 0x54, 0x00, 0x19, 0x93}))

do
   local handle = assert(io.open(OUT .. "/hello.luac", "rb"))
   local hello = handle:read("*a")
   handle:close()
   -- Cut inside the LUAC_INT / LUAC_NUM markers.
   write("truncated.luac", hello:sub(1, 20))
   -- Same chunk with all 8 bytes of the LUAC_INT marker reversed, which is
   -- what a big endian producer would write: 0x5678 stored most significant
   -- byte first instead of last.
   write("wrong_endian.luac", hello:sub(1, 15) .. str({0, 0, 0, 0, 0, 0, 0x56, 0x78}) .. hello:sub(24))
end

-- 4 KB of noise behind a real signature, from a fixed seed so it is stable.
do
   math.randomseed(20240220)
   local noise = {0x1B, 0x4C, 0x75, 0x61}
   for _ = 5, 4096 do noise[#noise + 1] = math.random(0, 255) end
   write("hostile_random.luac", str(noise))
end

-- A constant table claiming one string of a gigabyte.
write("hostile_sizes.luac", join(
   HEADER54,
   LUAC_INT_MARKER, LUAC_NUM_MARKER,
   {1},                              -- nupvalues of the main closure
   proto54({constants = 1, constant = {4, varint(0x3FFFFFFF)}})
))

-- A constant table claiming 200001 constants, past the 100k read cap.
write("hostile_constants.luac", join(
   HEADER54,
   LUAC_INT_MARKER, LUAC_NUM_MARKER,
   {1},
   proto54({constants = 200001})
))

-- 100 nested prototypes, past the depth cap of 64. The innermost carries a
-- sink name, so a walker that kept going would report 802 and one that stopped
-- at the cap would not; the spec asserts on that difference.
local function nested54(depth)
   if depth == 0 then
      return proto54({source = "@deep.lua", constants = 1, constant = {4, sized("os.execute")}})
   end
   return proto54({children = 1, children_body = nested54(depth - 1)})
end

write("hostile_depth.luac", join(
   HEADER54,
   LUAC_INT_MARKER, LUAC_NUM_MARKER,
   {1},                                -- nupvalues of the main closure
   nested54(99)
))

-- A real 5.4 chunk with its version byte replaced by one that names no
-- release. Everything after byte 5 is still a well formed 5.4 header and a
-- well formed 5.4 prototype holding "os.execute", so a reader that defaults
-- to 5.4 gets a plausible 802 out of a file whose version it never knew.
do
   local handle = assert(io.open(OUT .. "/sink_exec.luac", "rb"))
   local sink = handle:read("*a")
   handle:close()
   assert(sink:byte(5) == 0x54, "sink_exec.luac is no longer a 5.4 chunk")
   write("unknown_version.luac", sink:sub(1, 4) .. str({0x99}) .. sink:sub(6))
end

print("fixtures written to " .. OUT)

