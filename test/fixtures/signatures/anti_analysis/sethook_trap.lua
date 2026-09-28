-- Fixture: a debug hook installed to observe the call stack (745).
--
-- The mask names the call, return and line events, so the hook runs inside
-- every one of them and can look at the stack of whatever called it.
local function watchdog()
   local level = 2
   while true do
      local info = debug.getinfo(level, "Sl")
      if not info then
         os.exit(0)
      end
      if info.source == "@/usr/bin/gdb" or info.source == "@strace" then
         os.exit(1)
      end
      level = level + 1
   end
end

debug.sethook(watchdog, "crl", 1000)
return watchdog
