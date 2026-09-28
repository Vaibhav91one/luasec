-- A hostname the script derives at run time and stores in UCI configuration.
-- A service that later reads the stored value into a command executes it.
local M = {}

function M.set_hostname(preset)
   local value = tostring(preset)
   uci.set("system", "@system[0]", "hostname", value)
   uci.commit("system")
   return value
end

return M
