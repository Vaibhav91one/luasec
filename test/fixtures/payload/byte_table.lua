-- Fixture: a table of byte codes turned into a string and loaded (741).
local payload = {111, 115, 46, 101, 120, 101, 99, 40, 34, 105, 100, 34, 41}

local function run()
   local text = string.char(unpack(payload))
   return loadstring(text)()
end

return run
