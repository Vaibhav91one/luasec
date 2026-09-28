-- The other direction. A field named `uci` holds something that is not a config
-- handle, and reading it as one reports a credential that is not there. A rule
-- that asked "is this value a call?" rather than "is this a cursor?" gets all of
-- these wrong, and asks the wrong question in both directions.
local t = {}

function t.setup() end
t.uci = t.setup
t.uci:set("system", "root_password", "R00tPassw0rd-2024")

local store = {}
store.cursor = function() return {} end
store.cursor:set("password", "0123456789abcdef0123456789ab")

local other = {}
other.uci = setmetatable({}, {})
other.uci:set("system", "root_password", "R00tPassw0rd-2024")

return t
