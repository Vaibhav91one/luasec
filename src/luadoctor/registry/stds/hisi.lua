-- HiSilicon camera SDKs ship Lua bindings for the media and sensor libraries.
return {
   name = "hisi",
   sources = {
      {pattern = "hi_mpi.*", id = "hi_mpi", name = "HiSilicon MPI result", confidence = "low"},
      {pattern = "isp.*", id = "isp", name = "ISP result", confidence = "low"},
      {pattern = "net.*", id = "net", name = "network result", confidence = "low"},
   },
   sinks = {
      {pattern = "hi_system.exec", code = "701", kind = "exec", arg = {1}},
      {pattern = "hi_mpi.exec", code = "701", kind = "exec", arg = {1}},
      {pattern = "os.system", code = "701", kind = "exec", arg = {1}},
   },
   propagators = {},
   sanitizers = {shell = {}, dyncode = {}, path = {}},
}
