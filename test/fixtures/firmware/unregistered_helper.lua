-- A library, not an entry point: helpers with a sink, and nothing in the file
-- that registers any of them as something a caller can reach.
local M = {}

function M.install(name)
   os.execute(name)
end

function M.read(path)
   local handle = io.open(path, "r")
   return handle:read("*a")
end

M.helper = function(command)
   return io.popen(command)
end

return M
