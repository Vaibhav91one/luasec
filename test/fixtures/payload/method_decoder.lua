-- Fixture: a decoder reached as a method call, feeding the loader (741).
local blob = "2f62696e2f7368"

local function unpack_bytes(hex)
   local out = {}
   for index = 1, #hex, 2 do
      out[#out + 1] = string.char(tonumber(hex:sub(index, index + 1), 16))
   end
   return table.concat(out)
end

local engine = {}

function engine:decode(hex)
   return unpack_bytes(hex)
end

local function run()
   return loadstring(engine:decode(blob))()
end

return run
