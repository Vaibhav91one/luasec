-- Fixture: a handler using the module the preload entry defines.
local util = require "preloaded_util"

local function go(host)
   util.run("ping -c1 " .. http.formvalue(host))
end

return go
