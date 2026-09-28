-- Rule module: secrets.
--
-- A detector is a function(ctx). It calls ctx:emit(code, node, extra) for each
-- finding. See src/luasec/rules/context.lua for what a context offers.
--
-- Code this module owns: see docs/rules.md.
local M = {}

local detectors = {}

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

return M
