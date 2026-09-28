-- A local table named _G, a metatable on a local table, ordinary global writes
-- and a module published into the cache: none of these changes the environment
-- another chunk runs in.
local _G = {}
local t = setmetatable({}, {__index = function() end})
local M = {}

function M.setup(helpers)
   _G.own = 1
   t.field = 2
   package.loaded["helper"] = helpers
   return package.path
end

return M
