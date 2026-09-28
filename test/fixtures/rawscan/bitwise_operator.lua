-- Lua 5.3 gave us `//`, `<<`, `>>` and `~`. LuaJIT is a 5.1 dialect with its own
-- `bit` library and none of these operators, so a version number alone would
-- call this file 5.1 and therefore fine. It is not.
local shifted = 1 << 2
local halved = 7 // 2
return shifted, halved
