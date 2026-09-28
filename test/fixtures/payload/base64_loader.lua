-- Fixture: a base64-decoded blob handed to the code loader (741).
local blob = "b2NobyBoaQ=="

local function unpack_it()
   local payload = base64decode(blob)
   return loadstring(payload)
end

return unpack_it
