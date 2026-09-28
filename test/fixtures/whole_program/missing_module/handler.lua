-- Fixture: the required module is not in the analyzed set.
local util = require "not_in_the_scan"

local function go(host)
   util.run("ping -c1 " .. http.formvalue(host))
end

return go
