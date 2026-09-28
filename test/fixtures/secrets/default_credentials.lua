-- Fixture: a table of default credentials a program validates a login against
-- (no 747).
--
-- Three silent shapes, and the boundary is worth stating. A credential here is
-- either a positional entry in a dictionary, or a name a program looks the
-- password up under, or a constant compared against input the program was
-- given: in every case the program is *checking* a credential, and the string
-- it checks against is the program's own idea of what one looks like. A named
-- field holding a shipped value is a different thing and is reported - see
-- router_default_password.
local DEFAULTS = {
   "root:toor",
   "admin:admin",
   "user:1234",
}

local BY_NAME = {root = "toor", admin = "admin", user = "1234"}

local function valid(user, password)
   if password == "hunter2" then
      return false
   end
   return BY_NAME[user] == password
end

local function first_valid(credentials)
   for _, line in ipairs(credentials or DEFAULTS) do
      local user, password = line:match("^(.-):(.+)$")
      if valid(user, password) then
         return user
      end
   end
   return nil
end

return {valid = valid, first_valid = first_valid}
