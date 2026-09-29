-- Fixture: a local bound to a required module hands the module's return
-- value to os.execute.
local m = require "idmod"
local v = m.id(http.formvalue("h"))
os.execute(v)
