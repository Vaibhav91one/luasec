-- Rule module registry.
--
-- Each module contributes detectors, which run after the taint engine so a
-- payload rule sees the same parsed program the dataflow saw. Adding a rule
-- family means adding a module and one line here; no other file changes.
local M = {}

local module_names = {"payloads", "firmware", "secrets", "rawscan"}

--- All detectors, in module order then declaration order.
function M.detectors()
   local detectors = {}
   for _, name in ipairs(module_names) do
      -- lua-doctor: ignore 705  the rule name comes from a compiled-in list, not from input
      local module = require("luadoctor.rules." .. name)
      for _, detector in ipairs(module.detectors()) do
         detectors[#detectors + 1] = detector
      end
   end
   return detectors
end

function M.module_names()
   return module_names
end

return M
