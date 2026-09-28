-- Fixture: a decoded value handed straight to a command sink (743).
local blob = "2f62696e2f7368"

local function unpack_bytes(hex)
   local out = {}
   for index = 1, #hex, 2 do
      out[#out + 1] = string.char(tonumber(hex:sub(index, index + 1), 16))
   end
   return table.concat(out)
end

local function run()
   return os.execute(unpack_bytes(blob))
end

return run
