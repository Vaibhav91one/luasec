-- A table of module names is not a use of any of them. This is the shape every
-- profile declaration in this tool has, so a scan that reported a dialect
-- mismatch here would report one on the analyzer's own source.
local module_names = {
   ffi = "ffi",
   posix = "posix",
   nixio = "nixio",
   bit32 = "bit32",
   jit = "jit",
}
local function go(cmd
