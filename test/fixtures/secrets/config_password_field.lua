-- Fixture: a credential read out of a configuration file (no 747).
--
-- The shape is a config section fielded by name and filled from a file, with an
-- empty default for the key the file does not carry. The names say secret and
-- the program says where the value comes from: there is no literal to embed.
local CONFIG = "/etc/config/network"

local function read(path)
   local handle = io.open(path, "r")
   if not handle then return nil end
   local values = {}
   for line in handle:lines() do
      local key, value = line:match("^%s*(%S+)%s*=%s*(%S+)")
      if key then values[key] = value end
   end
   handle:close()
   return values
end

local function section(name, path)
   return read(path or CONFIG) or {password = "", username = ""}
end

local function password_for(iface)
   local values = section(iface)
   return values.password or values["password"]
end

return {read = read, section = section, password_for = password_for}
