-- Fixture: a pass-through in a second file, which is what hides these bugs.
local sink_module = require "sink"

local M = {}

function M.forward(cmd)
   sink_module.run(cmd)
end

return M
