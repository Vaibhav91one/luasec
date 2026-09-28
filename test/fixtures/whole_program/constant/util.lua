-- Fixture: a helper in another file that executes whatever it is handed.
local M = {}

function M.run(cmd)
   os.execute(cmd)
end

return M
