-- Fixture: the only call across the boundary is a fixed one.
local util = require "util"

local function go()
   util.run("ping -c1 127.0.0.1")
end

return go
