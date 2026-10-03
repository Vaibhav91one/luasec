local obj = {}
local req = web.cgiToLuaTable(cgi)
obj:run(req)
