-- A loader that replaces the environment its caller runs in, installs a
-- metatable on the global table, and repoints the module search path.
local function load_with_blank_env(src)
   local chunk = load(src, "chunk")
   setfenv(1, {})
   debug.setfenv(1, {})
   debug.setmetatable(_G, {__index = function() return nil end})
   package.path = "/tmp/attacker/?.lua"
   package.cpath[1] = "/tmp/attacker/?.so"
   return chunk
end

return load_with_blank_env
