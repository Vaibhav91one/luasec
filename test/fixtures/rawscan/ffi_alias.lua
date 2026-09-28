-- Every LuaJIT binding names the FFI whatever it calls the local. Read as 5.1,
-- `C.system` below is a field lookup on nil, not a system() call, and the file
-- says nothing that would tell a reader which reading is right.
local f = require("ffi")
local C = f.C
C.system("id -un")
local function go(cmd
