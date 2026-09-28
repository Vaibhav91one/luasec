-- A backtick is a Lua 5.2 command literal. The parser behind this tool has
-- never read one, so this file cannot be parsed at all - which is exactly the
-- case the backtick finding has to survive.
local who = `id -un`
local function go(cmd
