-- Lua 5.4 lets a local carry an attribute. No version of Lua lets a global
-- carry one, and the parser behind this tool rejects the file outright.
COMMAND <const> = "id -un"
local function go(cmd
