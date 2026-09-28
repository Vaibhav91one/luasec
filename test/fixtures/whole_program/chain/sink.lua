-- Fixture: the file that executes.
local M = {}

function M.run(cmd)
   os.execute(cmd)
end

return M
