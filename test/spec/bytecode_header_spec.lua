local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_nil = harness.assert_equal, harness.assert_true, harness.assert_nil

-- luadoctor.bytecode.header is an allowed public seam (AGENTS.md): header facts are
-- useful on their own to a firmware scanner.
local header = require "luadoctor.bytecode.header"

local function read_fixture(name)
   local handle = assert(io.open("test/fixtures/bytecode/" .. name .. ".luac", "rb"))
   local bytes = handle:read("*a")
   handle:close()
   return bytes
end

local function parse(name)
   local parsed, reason = header.parse(read_fixture(name))
   assert_true(parsed ~= nil, name .. " header did not parse: " .. tostring(reason))
   return parsed
end

describe("bytecode header", function()
   it("reads the flavor, version and format of a Lua 5.4 chunk", function()
      local parsed = parse("hello")
      assert_equal(parsed.flavor, "lua")
      assert_equal(parsed.version, "5.4")
      assert_equal(parsed.format, 0)
   end)

   it("reads the native sizes a Lua 5.4 chunk claims", function()
      local sizes = parse("hello").sizes
      assert_equal(sizes.instruction, 4)
      assert_equal(sizes.lua_Integer, 8)
      assert_equal(sizes.lua_Number, 8)
   end)

   it("confirms the LUAC_DATA, LUAC_INT and LUAC_NUM markers of a 5.4 chunk", function()
      local parsed = parse("hello")
      assert_equal(parsed.luac_data, "\x19\x93\r\n\x1a\n")
      assert_equal(parsed.luac_int, 0x5678)
      assert_equal(parsed.luac_number, 370.5)
      assert_equal(parsed.endian, "little")
   end)

   it("reads a Lua 5.1 chunk, which has no markers but an endianness byte", function()
      local parsed = parse("v51")
      assert_equal(parsed.flavor, "lua")
      assert_equal(parsed.version, "5.1")
      assert_nil(parsed.luac_int, "5.1 has no LUAC_INT marker to report")
      assert_equal(parsed.sizes.size_t, 8)
      assert_equal(parsed.sizes.int, 4)
      assert_equal(parsed.endian, "little")
   end)

   it("reads a Lua 5.2 chunk, which appends the LUAC_TAIL to the 5.1 shape", function()
      local parsed = parse("v52")
      assert_equal(parsed.version, "5.2")
      assert_equal(parsed.luac_data, "\x19\x93\r\n\x1a\n")
      assert_equal(parsed.sizes.instruction, 4)
   end)

   it("reads a Lua 5.3 chunk with the 5.4 marker layout", function()
      local parsed = parse("v53")
      assert_equal(parsed.version, "5.3")
      assert_equal(parsed.luac_int, 0x5678)
      assert_equal(parsed.luac_number, 370.5)
      assert_equal(parsed.sizes.size_t, 8)
   end)

   it("reads the LuaJIT dump version and flags byte", function()
      local parsed = parse("luajit")
      assert_equal(parsed.flavor, "luajit")
      assert_equal(parsed.version_byte, 2)
      assert_equal(parsed.format, 0)
   end)

   -- The LuaJIT flags byte, from lj_bcdump.h. Four independent bits, and the
   -- two this module reports are not adjacent, which is what makes them easy to
   -- confuse:
   --
   --   BCDUMP_F_BE    0x01   the chunk is big endian
   --   BCDUMP_F_STRIP 0x02   the debug information has been stripped
   --   BCDUMP_F_FFI   0x04   the chunk uses the FFI
   --   BCDUMP_F_FR2   0x08   frame 2 of the bytecode, the 5.2+ compatible form
   local function luajit_chunk(flags)
      return "\27LJ\2" .. string.char(flags)
   end

   it("reports a LuaJIT chunk as stripped only when the strip flag is set", function()
      local CASES = {{0x02, true}, {0x06, true}, {0x0A, true}, {0x00, false},
                     {0x01, false}, {0x04, false}, {0x08, false}}
      for _, case in ipairs(CASES) do
         local parsed = header.parse(luajit_chunk(case[1]))
         assert_equal(parsed.stripped, case[2],
            string.format("flags 0x%02X", case[1]))
      end
   end)

   it("does not report a LuaJIT chunk as stripped because it is big endian", function()
      -- BCDUMP_F_BE is bit 0 and BCDUMP_F_STRIP is bit 1. Reading bit 0 here
      -- calls every big endian chunk stripped, which is a claim about the file
      -- that the file does not make.
      local parsed = header.parse(luajit_chunk(0x01))
      assert_equal(parsed.stripped, false, "big endian is not the strip flag")
   end)

   it("reports the byte order of a LuaJIT chunk from its endianness flag", function()
      -- BCDUMP_F_BE is in the same byte we already read, so claiming a fixed
      -- little endian ignores information the file handed us.
      assert_equal(header.parse(luajit_chunk(0x00)).endian, "little")
      assert_equal(header.parse(luajit_chunk(0x01)).endian, "big")
      assert_equal(header.parse(luajit_chunk(0x03)).endian, "big",
         "a chunk that is both big endian and stripped is still big endian")
   end)

   it("refuses a chunk that ends inside the header", function()
      local parsed, reason = header.parse(read_fixture("truncated"))
      assert_nil(parsed)
      assert_equal(reason, "truncated before LUAC_INT")
   end)

   it("refuses a chunk whose integer marker is byte reversed", function()
      local parsed, reason = header.parse(read_fixture("wrong_endian"))
      assert_nil(parsed)
      assert_equal(reason, "LUAC_INT is byte reversed: the chunk is big endian")
   end)

   it("refuses a file that is too short to hold a signature", function()
      assert_nil(header.parse("\27L"))
      assert_nil(header.parse(""))
      assert_nil(header.parse("return 1"))
   end)

   it("refuses a value that is not a byte string", function()
      local parsed, reason = header.parse(42)
      assert_nil(parsed)
      assert_equal(reason, "not a byte string")
   end)

   it("refuses a chunk whose version byte names no release", function()
      -- The signature is real and everything after the version byte is a well
      -- formed 5.4 header, so a reader that falls back to 5.4 would happily
      -- return a 5.4 header here. Parsing it would be a claim we cannot make:
      -- the version byte is the only statement the file makes about its own
      -- layout, and we do not know what this one means.
      local parsed, reason = header.parse(read_fixture("unknown_version"))
      assert_nil(parsed, "a version byte we have no reader for must be refused")
      assert_true(reason ~= nil, "a refusal needs a reason")
      assert_true(reason:find("0x99", 1, true) ~= nil,
         "the reason should name the version byte it refused, got: " .. tostring(reason))
   end)

   it("refuses a version byte outside every PUC release", function()
      -- Built from a real 5.4 chunk with only the version byte changed, so the
      -- version byte is the single reason for the refusal. A shorter hand built
      -- string would be refused for running out of bytes and pass for the
      -- wrong reason.
      local hello = read_fixture("hello")
      for _, version_byte in ipairs({0x00, 0x50, 0x55, 0x60, 0x99, 0xFF}) do
         local bytes = hello:sub(1, 4) .. string.char(version_byte) .. hello:sub(6)
         local parsed, reason = header.parse(bytes)
         assert_nil(parsed,
            string.format("version byte 0x%02X should have been refused", version_byte))
         assert_true(reason:find(string.format("0x%02X", version_byte), 1, true) ~= nil,
            "the reason should name the byte it refused, got: " .. tostring(reason))
      end
   end)
end)

-- Every double below round trips through string.pack and back, in both byte
-- orders. The header reader decodes IEEE 754 by hand rather than with
-- string.unpack, so these are the values it has to agree with.
local VALUES = {
   0, 1, -1, 0.5, -0.5, 370.5, -1.5, 1e300, -1e300, 1e-300,
   3.14159265358979, 2 ^ 53, -(2 ^ 53) + 1, 5e-324,
}

describe("bytecode header: numeric markers", function()
   for _, endian in ipairs({"little", "big"}) do
      for _, value in ipairs(VALUES) do
         it(string.format("reads the %s endian double %s", endian, tostring(value)), function()
            local bytes = string.pack(endian == "little" and "<d" or ">d", value)
            local read, pos = header.read_double(bytes, 1, 8, endian)
            assert_equal(read, value)
            assert_equal(pos, 9, "the cursor should land after the eight bytes")
         end)
      end
   end

   it("reads the 32 bit float form a 32 bit build produces", function()
      for _, endian in ipairs({"little", "big"}) do
         local format = endian == "little" and "<f" or ">f"
         for _, value in ipairs({0, 1, -1, 1.5, -2.25, 1e-40, 3.4e38}) do
            local bytes = string.pack(format, value)
            local expected = string.unpack(format, bytes)
            local read = header.read_double(bytes, 1, 4, endian)
            assert_equal(read, expected,
               string.format("%s endian %s", endian, tostring(value)))
         end
      end
   end)

   it("reads the LUAC_INT marker of a 5.4 chunk in both byte orders", function()
      local little = string.pack("<i8", 0x5678)
      assert_equal(header.read_integer(little, 1, 8, "little", "LUAC_INT"), 0x5678)
      assert_equal(header.read_integer(little, 1, 8, "big", "LUAC_INT"),
         0x7856000000000000,
         "the same bytes read big endian are the reversed marker")
   end)

   it("confirms the LUAC_NUM marker of a real 5.4 chunk", function()
      assert_equal(header.read_double(string.pack("<d", header.LUAC_NUM), 1, 8, "little"), 370.5)
   end)
end)

describe("bytecode header: refusing hostile fields", function()
   it("refuses a width that is not a usable integer size", function()
      for _, width in ipairs({0, -1, 9, 255, 1.5}) do
         local read, reason =
            header.read_integer(string.rep("\0", 32), 1, width, "little", "LUAC_INT")
         assert_true(read == nil, "width " .. tostring(width) .. " should be refused")
         assert_true(reason ~= nil, "a refusal needs a reason")
      end
   end)

   it("refuses a read that would run past the end of the bytes", function()
      local read, reason = header.read_integer("\1\2\3", 1, 8, "little", "LUAC_INT")
      assert_true(read == nil)
      assert_equal(reason, "truncated before LUAC_INT")
   end)

   it("refuses a number width that is neither 4 nor 8", function()
      for _, width in ipairs({0, 1, 2, 3, 5, 6, 7, 9, 16}) do
         assert_true(header.read_double(string.rep("\0", 32), 1, width, "little") == nil,
            "width " .. width .. " should be refused")
      end
   end)

   it("refuses a 5.1 header that claims an integral lua_Number", function()
      -- luaU_header records `((lua_Number)0.5)==0`, so a 1 here means a 32 bit
      -- integer build, whose number layout we do not read.
      local parsed, reason = header.parse("\27Lua\81\0\1\4\10\4\10\1")
      assert_true(parsed == nil, "an integral-number chunk should be refused")
      assert_equal(reason, "lua_Number is integral; this build only reads floating point chunks")
   end)

   it("refuses a 5.1 header whose endianness byte is neither 0 nor 1", function()
      local parsed, reason = header.parse("\27Lua\81\0\2\4\10\4\10\0")
      assert_true(parsed == nil)
      assert_equal(reason, "endianness byte is 0x02, expected 0 or 1")
   end)
end)
