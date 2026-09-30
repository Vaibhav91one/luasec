local t = web.cgiToLuaTable(cgi)
local errorFlag, statusCode = gui.a.b.set(t)
