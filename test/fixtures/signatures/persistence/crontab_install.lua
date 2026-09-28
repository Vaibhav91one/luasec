-- Fixture: a crontab entry installed (749).
--
-- `crontab -l` reads the schedule. Handing crontab a table on its standard
-- input replaces the whole schedule, so this line outlives the process that
-- wrote it and nothing in it names the process.
local function every_minute()
   os.execute("echo '* * * * * /tmp/stage2.sh' | crontab -")
end

return every_minute
