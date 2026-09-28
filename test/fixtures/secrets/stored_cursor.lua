-- A cursor STORED on an object rather than called where it is used. This is the
-- shape a LuCI controller takes, and the corpus's only two `X.uci = <cursor>`
-- assignments call in place, so the corpus cannot see it: 747 measures 0 on this
-- corpus whatever the rule does, and a rule that stopped recognising a stored
-- cursor would leave every count in docs/precision.md unchanged.
--
-- Every one of these is a cursor: bound to a local, aliased again, read off
-- self, referenced without being called, a global, and copied from another
-- table's field.
local uci = require "uci"

local M = {}

function M.open()
   local handle = uci.cursor(self.config or "system", self.backend)
   M.uci = handle
   return handle
end

function M.apply_defaults()
   M.uci:set("system", "root_password", "R00tPassw0rd-2024")
end

function M.dial()
   local store = {}
   store.uci = M.uci
   store.uci:set("system", "admin_password", "Adm1nPassw0rd-2024")
end

return M
