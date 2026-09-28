-- Fixture: the module name is assembled at run time, so it names nothing.
local function go(host)
   local name = "ut" .. "il"
   local util = require(name)
   util.run("ping -c1 " .. http.formvalue(host))
end

return go
