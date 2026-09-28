-- Every way firmware actually reaches a uci cursor, because the spelling is not
-- fixed: the module is aliased, the cursor lives on a table, it comes back from
-- a helper, it is require()d inline, or it is a global.
local muci = require "luci.model.uci"

local direct = muci.cursor()
direct:set("system", "root", "password", "R00tPassw0rd-2024")

local state = {}
state.uci = muci.cursor()
state.uci:set("wireless", "default", "key", "0123456789abcdef0123456789")

local returned = make_cursor()
returned:add("system", "guest", "password", "Gu3stPassw0rd-2024")

local inlined = require("uci").cursor()
inlined:set("system", "x", "password", "XxYyPassw0rd-2024")

local dotted = muci.cursor()
dotted.add("system", "y", "password", "YyZzPassw0rd-2024")
