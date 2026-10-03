local gui = {net = {}}
local t = web.cgiToLuaTable(cgi)
gui.net:set(t)
