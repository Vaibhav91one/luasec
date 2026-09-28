-- Fixture: pcall used the way it is meant to be used. Silent for 745.
--
-- Every call here keeps its result, or wraps something that cannot execute
-- anything, or opens a file for reading. None of them is hiding a failure.
local function optional_json(text)
   local ok, value = pcall(decode_json, text)
   if not ok then
      return nil, tostring(value)
   end
   return value
end

local function clock()
   local ok, seconds = pcall(os.time)
   if not ok then
      seconds = 0
   end
   return seconds
end

local function read_hostname()
   return pcall(io.open, "/etc/hostname", "r")
end

return {optional_json, clock, read_hostname}
