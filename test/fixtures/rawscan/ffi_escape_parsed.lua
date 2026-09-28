-- Parses cleanly, so the dialect answer has to come from the path that has an
-- AST, not only from the raw scan.
local ffi = require("ffi")
local C = ffi.C
C.system("id -un")
return C
