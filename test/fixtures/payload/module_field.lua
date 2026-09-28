-- Fixture: a decoded payload parked in a module field and loaded from there (741).
local M = {}

local function unpack_bytes(blob)
   local out = {}
   for index = 1, #blob, 2 do
      out[#out + 1] = string.char(tonumber(blob:sub(index, index + 1), 16))
   end
   return table.concat(out)
end

function M.install(blob)
   M.payload = unpack_bytes(blob)
   return loadstring(M.payload)
end

return M
