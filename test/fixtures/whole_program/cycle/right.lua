-- Fixture: the other half of the require cycle, and the file that executes.
local left = require "left"

local M = {}

function M.execute(cmd)
   os.execute(cmd)
end

return M
