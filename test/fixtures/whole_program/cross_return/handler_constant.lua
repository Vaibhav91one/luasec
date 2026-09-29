-- Fixture: a constant argument through the module's identity field must
-- not be reported as tainted reaching a sink.
local m = require "idmod"
os.execute(m.id("ls"))
