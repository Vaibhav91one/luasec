-- Fixture: a quoting helper in the module neutralizes the shell sink, and
-- must not raise 712.
local m = require "idmod"
os.execute("echo " .. m.q(http.formvalue("h")))
