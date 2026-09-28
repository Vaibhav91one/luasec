-- Fixture: the module field is a local function bound after the table is made.
local M = {}

local function helper(cmd)
   os.execute(cmd)
end

M.run = helper

return M
