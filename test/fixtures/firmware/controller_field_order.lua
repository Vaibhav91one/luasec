-- A controller with a field that is not a hook. The dispatcher walk reaches
-- this before the hook below, so a fault in the name test used to abort the
-- whole file and the hook's finding was never reached.
module("luci.controller.firewall", package.seeall)

local M = Map("fw", "Firewall")

function M.helper(x)
   return x
end

function M.on_after_commit(self)
   os.execute("/etc/init.d/firewall reload")
end

function index()
   entry({"admin", "firewall"}, call("on_after_commit"))
end

return M
