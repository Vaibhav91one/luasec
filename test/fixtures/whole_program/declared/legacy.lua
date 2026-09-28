-- Fixture: the Lua 5.1 `module` call, which names a module without a return.
module "legacy_tools"

local tonumber = tonumber

function run(cmd)
   os.execute(cmd)
end

function double(n)
   return tonumber(n) * 2
end
