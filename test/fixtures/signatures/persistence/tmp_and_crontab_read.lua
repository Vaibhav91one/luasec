-- Fixture: writes that install nothing. Silent for 749.
--
-- State under /tmp dies with the reboot, a per-user config file belongs to the
-- user, and `crontab -l` reads a schedule instead of replacing one. Reading a
-- boot file to see what it says is what a diagnostics page does, and the one
-- write here whose path is computed goes wherever the caller asked.
local function save_state(state)
   local handle = io.open("/tmp/app-state.json", "w")
   handle:write(state)
   handle:close()
end

local function read_boot_file(path)
   local handle = io.open(path or "/etc/rc.local", "r")
   if not handle then
      return ""
   end
   local text = handle:read("*a")
   handle:close()
   return text
end

local function show_schedule()
   return os.execute("crontab -l")
end

local function save_preference(value)
   local handle = io.open(os.getenv("HOME") .. "/.config/app/prefs", "w")
   handle:write(value)
   handle:close()
end

return {save_state, read_boot_file, show_schedule, save_preference}
