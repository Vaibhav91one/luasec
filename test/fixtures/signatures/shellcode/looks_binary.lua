-- Fixture: strings that look like blobs and are not. Silent for 746.
--
-- Base64 and hex both look random and are both text. A shell snippet kept in a
-- string is source, not bytes. A program that prints a file magic prints four
-- characters. A run of four NOPs is alignment. And a small structured record -
-- a config blob with a fixed layout and mostly zeroes - is not a program
-- either: its entropy is its length in distinct values, not a random draw.
local TOKEN = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAA"

local CONFIG_BLOB = "\0\1\0\0\0\2\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"

local SNIPPET = "local function main()\n   local ok = pcall(read_config)\n   if not ok then\n      return nil\n   end\n   return ok\nend\n"

local MAGIC_NOTE = "a Lua bytecode chunk starts with \\27Lua, an ELF with \\127ELF"

local PADDING = "\144\144\144\144\144"

local ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

return {TOKEN, CONFIG_BLOB, SNIPPET, MAGIC_NOTE, PADDING, ALPHABET}
