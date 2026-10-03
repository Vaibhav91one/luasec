local t = web.cgiToLuaTable(cgi)
local ok = gui.net:set(t)
return ok
