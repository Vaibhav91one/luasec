-- Fixture: a module that requires itself, which a loader would find in the cache.
local util = require "util"

local M = {}

function M.run(cmd)
   os.execute(cmd)
end

return M
