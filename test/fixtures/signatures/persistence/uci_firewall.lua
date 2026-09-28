-- Fixture: a firewall rule that opens a port (749).
--
-- A uci write to the firewall package is a rule the device enforces at boot.
-- Setting dest_port is what turns it into a listener reachable from the wan
-- side, which is the whole point of the rule.
local function open_port(port)
   uci.set("firewall.@rule[0].name=allow-stage2")
   uci.set("firewall.@rule[0].dest_port=" .. port)
   uci.set("firewall.@rule[0].src=wan")
   uci.commit("firewall")
end

return open_port
