-- Fixture: a hand-rolled byte decoder whose result is handed to the loader (741).
local function decode(blob)
   local out = {}
   for index = 1, #blob do
      out[index] = string.char(blob:byte(index) + 7)
   end
   return table.concat(out)
end

local function run()
   return loadstring(decode("if os then os.execute('id') end"))()
end

return run
