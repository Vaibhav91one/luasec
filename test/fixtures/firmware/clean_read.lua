-- Ordinary scratch work. "/etc/passwd" is world readable on a stock device, and
-- "/tmp/myshadowfile.txt" and "/tmp/etc/shadow" only contain the text of a
-- sensitive path: matching that text is not matching the path.
local function work()
   local scratch = io.open("/tmp/x", "w")
   local passwd = io.open("/etc/passwd", "r")
   local decoy = io.open("/tmp/myshadowfile.txt", "r")
   local nested = io.open("/tmp/etc/shadow", "r")
   scratch:write("hello")
   return passwd:read("*a"), decoy:read("*a"), nested:read("*a")
end

return work
