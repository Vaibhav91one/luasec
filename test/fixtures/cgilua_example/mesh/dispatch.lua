methods = {
   ["Rename"] = {["methodName"] = "Rename", ["methodHandler"] = renameNode},
}

function dispatch(name)
   local request = web.cgiToLuaTable(cgi)
   return methods[name]["methodHandler"](request, name)
end
