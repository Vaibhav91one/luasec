-- CGILua web backends. Request data arrives in the global `cgi` table
-- (`cgi["name"]`, `cgi.action`), through `web.cgiToLuaTable(cgi)`, and through
-- the globals `RowId`, `DBTable`, `NextPage` split off a button name; it
-- reaches a shell through the vendor wrappers `util.runShellCmd` and
-- `util.shellCmdOutput`, modelled here as full exec sinks.
return {
   name = "cgilua",
   global_sources = {
      {global = "cgi", id = "cgi", name = "CGILua request table", confidence = "certain"},
      {global = "RowId", id = "RowId", name = "CGILua row id", confidence = "high"},
      {global = "DBTable", id = "DBTable", name = "CGILua db table", confidence = "high"},
      {global = "NextPage", id = "NextPage", name = "CGILua next page", confidence = "high"},
   },
   sources = {
      {pattern = "web.cgiToLuaTable", id = "web.cgiToLuaTable", name = "CGILua request table", confidence = "certain"},
      {pattern = "web.cgiSearch", id = "web.cgiSearch", name = "CGILua request value", confidence = "high"},
      {pattern = "web.cgiFindButton", id = "web.cgiFindButton", name = "CGILua button value", confidence = "high"},
      {pattern = "web.cgiFindToken", id = "web.cgiFindToken", name = "CGILua token value", confidence = "high"},
      {pattern = "SAPI.Request.servervariable", id = "SAPI.Request.servervariable", name = "server variable", confidence = "high"},
      {pattern = "cgilua.cookies.get", id = "cgilua.cookies.get", name = "CGILua cookie", confidence = "medium"},
   },
   sinks = {
      {pattern = "util.runShellCmd", code = "701", kind = "exec", arg = {1}},
      {pattern = "util.shellCmdOutput", code = "701", kind = "exec", arg = {1}},
   },
   propagators = {},
   sanitizers = {shell = {}, dyncode = {}, path = {}},
}
