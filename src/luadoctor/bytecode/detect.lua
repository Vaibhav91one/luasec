-- Is this file precompiled Lua bytecode?
--
-- Two signatures exist in the wild: the PUC-Rio one, ESC "Lua" followed by a
-- version byte (0x51..0x54 for 5.1..5.4), and the LuaJIT one, ESC "LJ"
-- followed by a dump version byte. Everything else is source, or is not Lua at
-- all, and this module says so.
local detect = {}

local ESC = 0x1B
local PUC = "Lua"
local JIT = "LJ"

-- PUC-Rio encodes the version as (major * 16) + minor in one byte.
local PUC_VERSIONS = {
   [0x51] = "5.1",
   [0x52] = "5.2",
   [0x53] = "5.3",
   [0x54] = "5.4",
}

--- True when `bytes` starts with a recognized Lua bytecode signature.
function detect.is_bytecode(bytes)
   return detect.identify(bytes) ~= nil
end

--- Identify a bytecode file.
--
-- Returns a table describing the flavor and version, or nil when the bytes do
-- not carry a known signature. The result is deliberately small: it is only a
-- claim about the first few bytes, not a validation of the chunk.
--
--   flavor         "lua" or "luajit"
--   version_byte   the raw byte after the signature
--   version        "5.1".."5.4" for PUC, or the LuaJIT dump version
--   version_string what to show a human, e.g. "Lua 5.4" or "LuaJIT 2.x"
--   known          whether the version byte is one we recognize
function detect.identify(bytes)
   if type(bytes) ~= "string" or #bytes < 4 then return nil end
   if bytes:byte(1) ~= ESC then return nil end

   -- The PUC signature is ESC "Lua" and the version byte follows it.
   if bytes:sub(2, 4) == PUC then
      local version_byte = bytes:byte(5)
      if version_byte == nil then return nil end
      local version = PUC_VERSIONS[version_byte]
      return {
         flavor = "lua",
         version_byte = version_byte,
         version = version,
         version_string = version and ("Lua " .. version)
            or string.format("Lua (unknown version 0x%02X)", version_byte),
         known = version ~= nil,
      }
   end

   -- The LuaJIT signature is only ESC "LJ" (ljbcsave.h: BCDUMP_HEAD1..3); the
   -- dump version byte is the fourth.
   if bytes:sub(2, 3) == JIT then
      local version_byte = bytes:byte(4)
      if version_byte == nil then return nil end
      return {
         flavor = "luajit",
         version_byte = version_byte,
         version = "2.1",
         version_string = "LuaJIT 2.x",
         known = version_byte == 2,
      }
   end

   return nil
end

--- What a file that is not text looks like, or nil for source.
--
-- Known container magics are checked first (a gzip or a zip can start without a
-- NUL), then the rule git uses for "binary": a NUL byte in the first 8 KiB.
-- Lua source never contains one, so a file that does is not source, and lexing
-- it only turns its bytes into findings.
function detect.binary_kind(bytes)
   local head = bytes:sub(1, 8192)
   local four = head:sub(1, 4)
   if four == "hsqs" or four == "sqsh" then return "a squashfs image" end
   if four == "UBI#" then return "a UBI image" end
   if four == "\127ELF" then return "an ELF executable" end
   if four == "PK\3\4" then return "a zip archive" end
   if head:sub(1, 2) == "\31\139" then return "a gzip archive" end
   if head:sub(258, 262) == "ustar" then return "a tar archive" end
   if head:find("\0", 1, true) then return "binary data" end
   return nil
end

return detect
