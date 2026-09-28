-- Fixture: a handler reaching a helper declared with the module call.
local tools = require "legacy_tools"

local function go(host)
   tools.run("ping -c1 " .. http.formvalue(host))
end

return go
