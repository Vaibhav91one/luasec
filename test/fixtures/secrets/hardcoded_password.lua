-- Fixture: a password written into the program itself (747).
local telnet_password = "s3cr3t-pass"

local function login(host)
   local socket = require("socket").tcp()
   socket:connect(host, 23)
   socket:send("admin\n" .. telnet_password .. "\n")
end

return login
