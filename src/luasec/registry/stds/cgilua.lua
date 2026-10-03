-- CGILua web backends. Request data arrives in the global `cgi` table
-- (`cgi["name"]`, `cgi.action`), through `web.cgiToLuaTable(cgi)`, and through
-- the globals `RowId`, `DBTable`, `NextPage` split off a button name; it
-- reaches a shell through the vendor wrappers `util.runShellCmd` and
-- `util.shellCmdOutput`, modelled here as exec sinks whose command argument is a partial filter.
-- Settings live in a database read and written through `db.*`: a value a page
-- writes there and a backend reads back into a command is one flow (729).
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
      -- Both wrappers strip ; ` $ & | < > from the command, not from `options`,
      -- and leave ( ) and newline: position 1 is a partial filter, options is not.
      {pattern = "util.runShellCmd", code = "701", kind = "exec", arg = {1, 4},
         filters = {[1] = ";`$&|<>"}},
      {pattern = "util.shellCmdOutput", code = "701", kind = "exec", arg = {1, 2},
         filters = {[1] = ";`$&|<>"}},
   },
   -- The mesh JSON-RPC handlers are called as `handler(methodObj, method)` from a
   -- route table the analysis does not follow; methodObj is the decoded request.
   entry_points = {
      {pattern = "*Handler", arg = {1}, id = "methodObj", name = "mesh request object", confidence = "medium"},
   },
   -- db.setAttribute(table, keyField, key, column, value), db.insert(table, row),
   -- db.update(table, row, rowid); db.getAttribute(table, keyField, key, column)
   -- and the row readers, which name a table but not a column.
   store_writes = {
      {pattern = "db.setAttribute", store = "db", table = 1, column = 4, value = 5},
      {pattern = "db.insert", store = "db", table = 1, row = 2},
      {pattern = "db.update", store = "db", table = 1, row = 2},
   },
   store_reads = {
      {pattern = "db.getAttribute", store = "db", table = 1, column = 4},
      {pattern = "db.getRow", store = "db", table = 1},
      {pattern = "db.getRowWhere", store = "db", table = 1},
      {pattern = "db.getRows", store = "db", table = 1},
      {pattern = "db.getRowsWhere", store = "db", table = 1},
      {pattern = "db.getTable", store = "db", table = 1},
   },
   propagators = {},
   sanitizers = {shell = {}, dyncode = {}, path = {}},
}
