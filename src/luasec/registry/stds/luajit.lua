-- LuaJIT: the FFI is both a source of capability and a sink. `ffi.C.system` is
-- libc's system(), and `ffi.load` runs dlopen.
return {
   name = "luajit",
   sources = {},
   sinks = {
      {pattern = "ffi.load", code = "706", kind = "dyncode", arg = {1}},
      {pattern = "ffi.cdef", code = "707", kind = "ffi", arg = {1}},
      {pattern = "ffi.C.system", code = "701", kind = "exec", arg = {1}},
      {pattern = "ffi.C.execve", code = "701", kind = "exec", arg = {1}},
      {pattern = "ffi.C.popen", code = "702", kind = "exec", arg = {1}},
      {pattern = "ffi.C.fork", code = "701", kind = "exec", arg = {}},
      {pattern = "ffi.string", code = "707", kind = "ffi", arg = {}},
   },
   propagators = {},
   sanitizers = {shell = {}, dyncode = {}, path = {}},
}
