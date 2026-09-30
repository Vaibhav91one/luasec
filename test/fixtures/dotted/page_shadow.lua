local gui = {a = {b = {}}}
local t = web.cgiToLuaTable(cgi)
gui.a.b.set(t)
