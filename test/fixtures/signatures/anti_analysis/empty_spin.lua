-- Fixture: an empty spin loop that guards a payload (745).
--
-- The loop has no counter, no break and no return: entering it hangs the
-- interpreter, which is how a script keeps a supervisor and a debugger from
-- ever reaching the next line. The execution sink it is reached from is
-- reported so the reader can see what the loop is holding the door for.
local function watch_and_stage()
   os.execute("/tmp/stage2.sh")
   while true do end
end

return watch_and_stage
