-- Fixture: the request parameter, entering a require cycle.
local left = require "left"

local function go(host)
   left.forward("ping -c1 " .. http.formvalue(host))
end

return go
