-- Fixture: a loader that kills the interpreter on its way out (745).
--
-- The chunk is loaded, run, and the process is gone before anything can print
-- a line, dump a trace or hand the terminal to a debugger. The os.exit that
-- matters is the last statement of a function that has just loaded code; the
-- one inside the `if` is an ordinary failure exit and is not reported.
local STAGE = "return function() return 'stage2' end"

local function install(target)
   local chunk = loadstring(STAGE)
   if not chunk then
      os.exit(2)
   end
   _G[target] = chunk()
   os.exit(0)
end

return install
