-- Fixture: a router script that ships the admin password in the program (747).
--
-- A true positive of the shape this rule exists for: a credential nobody on the
-- device chose, written where anyone who reads the firmware image can read it.
-- The username is not a secret, so it is not reported; the password is.
local uci = require "luci.model.uci"
local cursor = uci.cursor()

local ADMIN_USER = "root"
local ADMIN_PASSWORD = "admin"

function apply(iface)
   cursor:set("system.@user[0].username", ADMIN_USER)
   cursor:set("system.@user[0].password", ADMIN_PASSWORD)
   cursor:commit("system")
   return iface
end

return apply
