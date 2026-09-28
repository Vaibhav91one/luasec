-- Fixture: a loop over a table of credential lines, sent to a socket (748).
local credentials = {
   "root:toor",
   "admin:admin",
   "user:1234",
}

local function try_all(host, port)
   for _, line in ipairs(credentials) do
      local client = socket.tcp()
      client:settimeout(2000)
      if client:connect(host, port) then
         local banner = client:receive("*l")
         client:send(line)
         client:close()
      end
   end
end

return try_all
