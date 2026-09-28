-- Fixture: the file that reads the request parameter.
local middle = require "middle"

local function go(host)
   middle.forward("ping -c1 " .. http.formvalue(host))
end

return go
