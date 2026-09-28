-- Fixture: a credential scanner - connect, read the banner, send the credential (748).
local socket = require("socket")

local targets = {"192.168.1.1", "10.0.0.1"}
local username = "root"
local password = "admin"

local function scan()
   for _, host in ipairs(targets) do
      local client = socket.tcp()
      client:settimeout(3000)
      if client:connect(host, 23) then
         local banner = client:receive("*l")
         client:send(username .. ":" .. password .. "\n")
         local answer = client:receive("*l")
         if answer and answer:find("Login") then
            client:send(password .. "\n")
         end
         client:close()
      end
   end
end

return scan
