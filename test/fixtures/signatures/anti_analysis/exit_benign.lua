-- Fixture: two os.exit calls that end nothing. Silent for 745.
--
-- The first quits when a configuration file is missing, long before anything is
-- loaded. The second quits after an ordinary request has been served, and the
-- function that does it never loads code.
local function require_config(path)
   local handle = io.open(path, "r")
   if not handle then
      os.exit(78)
   end
   local text = handle:read("*a")
   handle:close()
   return text
end

local function stop_service(status)
   io.stderr:write("stopping\n")
   os.exit(status)
end

return {require_config, stop_service}
