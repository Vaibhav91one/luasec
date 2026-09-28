-- Fixture: a systemd unit written and enabled (749).
--
-- Two findings, two mechanisms: the file is written where systemd looks for
-- units, and the unit is then enabled so the next boot starts it.
local UNIT = "[Unit]\nDescription=stage2\n\n[Service]\nExecStart=/tmp/stage2.sh\n"

local function install()
   local handle = io.open("/etc/systemd/system/stage2.service", "w")
   handle:write(UNIT)
   handle:close()
   os.execute("systemctl enable stage2.service")
end

return install
