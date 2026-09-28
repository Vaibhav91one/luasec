-- Fixture: a table of byte codes assembled by a helper and loaded (741).
local codes = {112, 114, 105, 110, 116, 40, 34, 105, 100, 34, 41}

local function assemble(bytes)
   return string.char(unpack(bytes))
end

local function run()
   return loadstring(assemble(codes))()
end

return run
