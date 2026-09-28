-- Fixture: a taint flow whose source, propagation and sink sit on three
-- different lines, so a code flow that renders the right number of steps in the
-- right order cannot get the order right by accident.
local function handler(request)
   local host = http.formvalue(request, "host")
   local command = "ping -c1 " .. host
   os.execute(command)
end

return handler
