-- Fixture: a decoded chunk handed to dofile, which is both a loader and a sink.
local function decode(blob)
   local out = {}
   for index = 1, #blob, 2 do
      out[#out + 1] = string.char(tonumber(blob:sub(index, index + 1), 16))
   end
   return table.concat(out)
end

local function run(blob)
   return dofile(decode(blob))
end

return run
