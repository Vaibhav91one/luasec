-- LuCI: the OpenWrt web interface. Its handlers are the most common place where
-- an HTTP parameter reaches a shell command on a router.
return {
   name = "luci",
   sources = {
      {pattern = "luci.http.formvalue", id = "luci.http.formvalue",
         name = "LuCI request parameter", confidence = "certain"},
      {pattern = "luci.http.formvalue.*", id = "luci.http.formvalue",
         name = "LuCI request parameter", confidence = "certain"},
      {pattern = "luci.dispatcher.context.formvalue", id = "luci.dispatcher.context.formvalue",
         name = "LuCI request parameter", confidence = "certain"},
      {pattern = "luci.dispatcher.context.formvalue.*", id = "luci.dispatcher.context.formvalue",
         name = "LuCI request parameter", confidence = "certain"},
      {pattern = "luci.dispatcher.createtree", id = "luci.dispatcher.createtree",
         name = "LuCI dispatcher node", confidence = "low"},
      {pattern = "luci.ip.*", id = "luci.ip", name = "parsed IP or host", confidence = "low"},
      {pattern = "luci.time.now", id = "luci.time.now", name = "device clock", confidence = "low"},
   },
   sinks = {
      {pattern = "luci.sys.call", code = "701", kind = "exec", arg = {1}},
      {pattern = "luci.util.uci.*", code = "722", kind = "config", arg = {2, 3, 4}},
      {pattern = "luci.dispatcher.createtree", code = "724", kind = "expose", arg = {}},
   },
   propagators = {
      {pattern = "luci.util.shellquote", arg = {1}},
      {pattern = "luci.util.trim", arg = {1}},
   },
   sanitizers = {
      shell = {"luci.util.shellquote"},
      dyncode = {},
      path = {},
   },
}
