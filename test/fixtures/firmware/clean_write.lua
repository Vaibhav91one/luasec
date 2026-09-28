-- Scratch work the script owns, a read of a flash partition, and a directory
-- that merely sits below /tmp: its path is not /etc/config/network.
local function work()
   local scratch = io.open("/tmp/x", "w")
   local backup = io.open("/tmp/etc/config/network", "w")
   local readback = io.open("/dev/mtd0", "r")
   scratch:write("hello")
   backup:close()
   return readback
end

return work
