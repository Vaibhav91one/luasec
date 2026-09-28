-- Fixture: credentials handed to parameters the program itself named (747).
local function require_login(user, password)
   if user == "root" then
      return password == "toor"
   end
   return false
end

local function dial(host, port)
   return require_login("root", "toor"), host, port
end

return {require_login = require_login, dial = dial}
