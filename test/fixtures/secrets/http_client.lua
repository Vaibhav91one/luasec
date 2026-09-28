-- Fixture: a client loop that opens a connection and sends no credential (no 748).
local function fetch(url, host, port, path)
   for _, attempt in ipairs({1, 2, 3}) do
      local client = socket.tcp()
      client:settimeout(5000)
      if client:connect(host, port) then
         client:send("GET " .. path .. " HTTP/1.0\r\n")
         local body = client:receive("*a")
         client:close()
         return body
      end
   end
   return nil
end

local function poll(handler)
   while true do
      local client = socket.tcp()
      if client:connect("127.0.0.1", 8080) then
         local line = client:receive("*l")
         handler(line)
         client:close()
      end
   end
end

return {fetch = fetch, poll = poll}
