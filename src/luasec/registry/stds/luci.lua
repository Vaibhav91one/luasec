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
      -- luci.http.getenv("REMOTE_ADDR") and the HTTP_* headers are how a LuCI
      -- handler reads the request, and they are exactly what the caller picks.
      -- Certain for the same reason formvalue is: the value is the request, not
      -- an inference about where it might come from.
      {pattern = "luci.http.getenv", id = "luci.http.getenv",
         name = "LuCI request environment", confidence = "certain"},
      {pattern = "luci.http.getenv.*", id = "luci.http.getenv",
         name = "LuCI request environment", confidence = "certain"},
      {pattern = "luci.time.now", id = "luci.time.now", name = "device clock", confidence = "low"},
   },
   -- luci.dispatcher calls a controller module's exported functions as
   -- `stem_action(node, <url segments>)`. The node name and every segment after
   -- it are the request path, so in a controller file every argument a handler
   -- is called with is request data.
   entry_points = {
      {pattern = "*", file = "*/controller/*.lua", arg = "*",
         name = "LuCI dispatcher argument", confidence = "medium", channel = "web"},
   },
   sinks = {
      {pattern = "luci.sys.call", code = "701", kind = "exec", arg = {1}},
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
