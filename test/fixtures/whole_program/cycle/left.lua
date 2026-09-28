-- Fixture: half of a require cycle. left needs right and right needs left.
local right = require "right"

local M = {}

function M.forward(cmd)
   return right.execute(cmd)
end

return M
