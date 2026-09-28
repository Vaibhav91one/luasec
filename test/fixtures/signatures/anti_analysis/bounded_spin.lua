-- Fixture: two loops that do leave. Silent for 745.
--
-- The first is the anti-debug idiom without the anti-debug: it walks the call
-- stack to find its own caller and returns as soon as it runs out of frames.
-- The second is an ordinary counted loop.
local function caller_frame(level)
   while true do
      local info = debug.getinfo(level, "Sl")
      if not info then return "bottom", 0 end
      if info.source == "[C]" then return "c frame", 0 end
      level = level + 1
      if level > 64 then return "too deep", 0 end
   end
end

local function countdown(limit)
   local total = 0
   while limit > 0 do
      total = total + limit
      limit = limit - 1
   end
   return total
end

return {caller_frame, countdown}
