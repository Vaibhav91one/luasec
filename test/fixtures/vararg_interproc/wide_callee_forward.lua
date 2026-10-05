-- A handler forwards its vararg into a callee that takes two positional
-- arguments before its own vararg. In Lua the forwarded values fill `a`, `b` and
-- then `...`, so the callee's vararg holds attacker data and not binding to it
-- loses the flow.
local function sink_fn(a, b, ...)
	os.execute(table.concat({...}, " "))
end

local function handler(...)
	sink_fn("fixed", "also fixed", ...)
end