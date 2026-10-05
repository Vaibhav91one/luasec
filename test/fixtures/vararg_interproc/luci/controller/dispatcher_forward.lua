-- Reduced from luci-app-commands' controller: a dispatcher handler whose vararg
-- is handed to a callee that reads its own vararg.
function action_run(...)
	execute_command(callback, ...)
end

function execute_command(callback, ...)
	os.execute(parse_cmdline(...))
end

local function parse_cmdline(...)
	return table.concat({...}, " ")
end
