local handlers = {login = doLogin, set = doSet}

local req = web.cgiToLuaTable(cgi)
handlers[cgi["op"]](req)
