-- The FFI is a LuaJIT capability and nothing else. Read under a standard that
-- does not have it, `ffi.C.system` is not a system() call - it is a field
-- lookup on a module that will be nil at run time. The file says neither; only
-- the operator's --std does.
local ffi = require("ffi")
local C = ffi.C
C.system("id -un")
local function go(cmd
