-- Fixture: a require of a name no scanned path ends with. The source tree is
-- not the image's /usr/lib/lua layout, which is where the module really lives.
local util = require "vendor.net.util"

local function go(host)
   util.run("ping -c1 " .. http.formvalue(host))
end

return go
