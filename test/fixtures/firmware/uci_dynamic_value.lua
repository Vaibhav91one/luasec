-- An OpenWrt firewall helper that adds a rule whose name is computed at run
-- time. A service that reads the rule back and interpolates its name into a
-- command turns this into remote code execution.
local M = {}

function M.add_rule(name)
   uci.add("firewall", "rule", name)
   uci.commit("firewall")
   return name
end

return M
