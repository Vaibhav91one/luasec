-- A method call whose receiver resolves to a local function. One line of
-- ordinary Lua, and it used to abort the entire scan with "attempt to get
-- length of a number value": the argument loop read `#index - 2`, which Lua
-- parses as the length of `index` minus two.
local function handler(opts, value)
   return opts
end

local config = {}

config:add("title", "x")
handler:add("title", "y")

return config
