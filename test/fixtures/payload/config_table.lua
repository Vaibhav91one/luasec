-- Fixture: a decoded payload built into a configuration table and loaded by key (741).
local function decode(blob)
   local out = {}
   for index = 1, #blob, 2 do
      out[#out + 1] = string.char(tonumber(blob:sub(index, index + 1), 16))
   end
   return table.concat(out)
end

local config = {
   script = decode("6f732e65786563757465206f7363"),
}

local function run()
   return loadstring(config.script)()
end

return run
