-- OpenWrt: the Lua layer shipped in the router firmware itself.
return {
   name = "openwrt",
   sources = {
      {pattern = "uci.get", id = "uci.get", name = "OpenWrt UCI value", confidence = "high"},
      {pattern = "uci.get.*", id = "uci.get", name = "OpenWrt UCI value", confidence = "high"},
      {pattern = "uci.get_all", id = "uci.get_all", name = "OpenWrt UCI config", confidence = "high"},
      {pattern = "uci.get_bool", id = "uci.get_bool", name = "OpenWrt UCI value", confidence = "high"},
      {pattern = "uci.get_first", id = "uci.get_first", name = "OpenWrt UCI value", confidence = "high"},
      {pattern = "luci.model.uci.get", id = "luci.model.uci.get", name = "LuCI UCI value", confidence = "high"},
      {pattern = "luci.model.uci.get_all", id = "luci.model.uci.get", name = "LuCI UCI config", confidence = "high"},
      {pattern = "ubus.call", id = "ubus.call", name = "ubus RPC result", confidence = "medium"},
      {pattern = "ubus.call.*", id = "ubus.call", name = "ubus RPC result", confidence = "medium"},
      {pattern = "ubus.connect", id = "ubus.connect", name = "ubus connection", confidence = "medium"},
      {pattern = "nixio.getenv", id = "nixio.getenv", name = "process environment", confidence = "medium"},
   },
   sinks = {
      {pattern = "nixio.process.execute", code = "701", kind = "exec", arg = {1}},
      {pattern = "nixio.process.exec", code = "701", kind = "exec", arg = {1}},
      -- `nixio.exec` is overloaded and the two forms disagree about where the
      -- command is:
      --     nixio.exec(command)                  -- first
      --     nixio.exec("/bin/sh", "-c", command)  -- third, and the dangerous one
      -- Declaring only the first left every shell call silent, which is the form
      -- OpenWrt code actually writes. Both positions are declared, so both
      -- report.
      --
      -- What this over-approximates: a third argument of a DIRECT call is an
      -- argv element, and nixio.exec hands it to execvp rather than to a shell,
      -- so `nixio.exec("/usr/bin/tool", "--label", tainted)` is reported where
      -- nixio itself treats it as an option. No corpus file does that. Telling
      -- the two forms apart needs a per-position guard -- position 3 counting
      -- only when position 2 is the literal "-c" -- and the sink declaration has
      -- no field for one.
      {pattern = "nixio.exec", code = "701", kind = "exec", arg = {1, 3}},
      {pattern = "posix.exec", code = "701", kind = "exec", arg = {1}},
      {pattern = "posix.exec.*", code = "701", kind = "exec", arg = {1}},
      {pattern = "posix.spawn", code = "701", kind = "exec", arg = {1}},
      {pattern = "luci.sys.call", code = "701", kind = "exec", arg = {1}},
      {pattern = "luci.util.uci.*", code = "722", kind = "config", arg = {2, 3, 4}},
      {pattern = "uci.set", code = "722", kind = "config", arg = {4}},
      {pattern = "uci.add", code = "722", kind = "config", arg = {4}},
      {pattern = "uci.sets", code = "722", kind = "config", arg = {2}},
   },
   propagators = {
      {pattern = "luci.util.pcdata", arg = {1}},
      {pattern = "luci.sys.uniqueid", arg = {}},
      {pattern = "jsonc.parse", arg = {1}},
      {pattern = "json.decode", arg = {1}},
      {pattern = "cjson.decode", arg = {1}},
      {pattern = "nixio.fs.readfile", arg = {1}},
   },
   sanitizers = {
      shell = {"luci.util.shellquote"},
      dyncode = {},
      path = {},
   },
}
