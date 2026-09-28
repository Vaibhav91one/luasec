-- Fixture: a scanner whose connect and send live in a helper the loop calls (748).
local socket = require("socket")

local function attempt(host, port, password)
   local client = socket.tcp()
   client:settimeout(2000)
   if client:connect(host, port) then
      local banner = client:receive("*l")
      client:send("root:" .. password .. "\n")
      client:close()
   end
end

local function scan(targets)
   for _, host in ipairs(targets) do
      attempt(host, 23, "admin")
   end
end

return scan
