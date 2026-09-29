-- Fixture: a required module's return value is handed to os.execute as a
-- nested call argument.
local m = require "idmod"
os.execute(m.id(http.formvalue("h")))
