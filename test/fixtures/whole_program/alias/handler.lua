-- Fixture: a request parameter handed to a helper in a required module.
local util = require "util"

local function go(host)
   util.run("ping -c1 " .. http.formvalue(host))
end

return go
