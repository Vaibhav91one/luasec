-- The field holds a cursor on one path and a boolean on the other. Which one it
-- is depends on which way the program went, so the field is read as a cursor:
-- deciding it by source order meant a later `M.uci = true` inside a branch
-- erased an earlier `M.uci = uci.cursor()` for the whole file, and the
-- credential was not reported.
local M = {}

M.uci = require("uci").cursor()
if flag then M.uci = true end
M.uci:set("system", "root", "password", "R00tPassw0rd-2024")

return M
