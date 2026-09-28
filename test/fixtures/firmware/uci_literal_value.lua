-- Configuration written entirely from literals: a static value the author chose,
-- not something a caller can influence.
local M = {}

function M.reset()
   uci.set("system", "@system[0]", "hostname", "OpenWrt")
   uci.set("system", "@system[0]", "timezone", "UTC")
   uci.commit("system")
end

return M
