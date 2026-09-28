-- A loader that replaces the environment the loaded chunk will see, installs a
-- metatable on the global table, and repoints the module search path.
local function load_with_blank_env(src)
   local chunk = load(src, "chunk")
   setfenv(chunk, {})
   debug.setfenv(chunk, {})
   debug.setmetatable(_G, {__index = function() return nil end})
   package.path = "/tmp/attacker/?.lua"
   package.cpath[1] = "/tmp/attacker/?.so"
   return chunk
end

return load_with_blank_env
