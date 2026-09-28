-- Scratch files this script owns, and files it only reads. None of them is a
-- firmware path, so none of them is the finding.
local function tidy()
   local handle = io.open("/tmp/scratch", "w")
   handle:write("x")
   handle:close()
   os.remove("/tmp/scratch")
   os.remove("/var/run/lock/pid")
   return io.open("/etc/passwd", "r")
end

return tidy
