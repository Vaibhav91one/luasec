-- A cleanup routine that deletes the device's own service scripts, moves its
-- boot file aside and rewrites its network configuration.
local function clean(name)
   os.remove("/etc/init.d/firewall")
   os.remove("/usr/bin/telnetd")
   os.remove("/etc/config/network")
   os.remove("/etc/rc.local")
   os.rename("/etc/rc.local", "/tmp/rc.local.bak")
   os.remove("/etc/init.d/" .. name)
   return os.remove("/tmp/scratch")
end

return clean
