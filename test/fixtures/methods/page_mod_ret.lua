local svc = require "svc"
local req = web.cgiToLuaTable(cgi)
os.execute("ret " .. svc:id(req.name))
