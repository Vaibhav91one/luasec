-- Fixture: a NOP sled built one byte at a time (746).
--
-- A run of 0x90 is alignment padding in a program and nothing else: a Lua
-- string of them is not text, and a string.char that spells them out is
-- writing the bytes of something that will be run.
local padding = string.char(
   144, 144, 144, 144, 144, 144, 144, 144, 144, 144,
   144, 144, 144, 144, 144, 144)

local handle = io.open("/tmp/blob.bin", "wb")
handle:write(padding)
handle:close()

return padding
