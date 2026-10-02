routes = {
   ["Login"] = {["methodName"] = "Login", ["methodHandler"] = doLogin},
   ["Set"] = {["methodName"] = "Set", ["methodHandler"] = doSet},
}

function dispatch()
   local req = web.cgiToLuaTable(cgi)
   local name = cgi["RequestMethod"]
   local status = routes[name]["methodHandler"](req, name)
   return status
end
