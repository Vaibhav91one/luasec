-- Reduced from luci-app-commands' controller: a dispatcher handler whose vararg
-- is handed to a callee that reads its own vararg, and so on to a sink.
--
-- Two deviations from the real file are deliberate, and both are limitations of
-- the analyser rather than of the binding under test. They are named here so
-- that nobody reads this fixture as the whole story:
--
--   * `local function` rather than `function`, because callgraph.resolve_callee
--     follows a callee through `item.used_values[node.var]` and a global
--     `function f(...)` declaration has no var to follow -- a global callee is
--     not a call site at all.
--   * `local cmd = parse_cmdline(...)` rather than `os.execute(parse_cmdline(...))`,
--     because callgraph.call_sites only visits a call that is a whole Eval item,
--     so one nested in an argument is never bound.
--
-- The order is the real file's (parse_cmdline :133, execute_command :156,
-- action_run :198): `local function` is a local declaration, so a handler
-- written above its callee names a local that is still nil at the call.
local function parse_cmdline(...)
	return table.concat({...}, " ")
end

local function execute_command(callback, ...)
	local cmd = parse_cmdline(...)
	os.execute(cmd)
end

local function action_run(...)
	execute_command(callback, ...)
end