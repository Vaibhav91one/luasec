-- Fixture: the command is fixed at parse time, nothing to inject.
local M = {}

function M.healthcheck()
   os.execute("ping -c1 127.0.0.1 > /dev/null")
   return true
end

return M
