local svc = require "svc"
local req = web.cgiToLuaTable(cgi)
svc:run(req)
