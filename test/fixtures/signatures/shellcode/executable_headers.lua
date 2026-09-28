-- Fixture: an ELF and a PE header written out as bytes (746).
--
-- Neither header is the finding on its own. What makes them findings is that
-- what follows the header is not text: a Lua string of printable characters
-- that begins "MZ" is a message, and a program is not a message.
local ELF = "\127ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0\76\0"
local PE = "MZ\144\0\3\0\0\0\4\0\0\0\255\255\0\0\216\66\69\88"

local function write_both(directory)
   local first = io.open(directory .. "/loader.elf", "wb")
   first:write(ELF)
   first:close()
   local second = io.open(directory .. "/loader.exe", "wb")
   second:write(PE)
   second:close()
end

return {write_both, ELF, PE}
