-- Fixture: a debug hook that only counts instructions. Silent for 745.
--
-- A count-only hook observes nothing about the call stack, so it is the
-- instrumentation idiom (a profiler, a sandbox budget) and not a trap.
local ticks = 0
local function on_tick()
   ticks = ticks + 1
end

debug.sethook(on_tick, "", 100000)
debug.sethook()
return ticks
