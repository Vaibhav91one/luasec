-- A firmware updater: it rewrites an image partition and the network config a
-- service reads at boot. Nothing here needs to be attacker controlled for the
-- device to stay compromised across a reboot.
local function flash_update(payload)
   local mtd = io.open("/dev/mtd0", "w")
   mtd:write(payload)
   local network = io.open("/etc/config/network", "w")
   network:write("config interface 'lan'")
   mtd:close()
   network:close()
end

return flash_update
