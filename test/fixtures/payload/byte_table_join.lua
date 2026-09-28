-- Fixture: a byte table handed to a plain joiner, then loaded (741).
local body = {114, 101, 116, 117, 114, 110, 32, 49}

local function join(parts)
   return table.concat(parts, "")
end

local function run()
   return loadstring(join(body))()
end

return run
