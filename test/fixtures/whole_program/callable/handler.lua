-- Fixture: a module required for the function it returns, called directly.
local run = require "runner"

local function go(host)
   run("ping -c1 " .. http.formvalue(host))
end

return go
