-- Fixture: a decoded value concatenated into a command that then runs (743).
local function from_hex(blob)
   return (blob:gsub("%x%x", function(pair)
      return string.char(tonumber(pair, 16))
   end))
end

local function run()
   os.execute("sh -c " .. from_hex("2f62696e2f7368"))
end

return run
