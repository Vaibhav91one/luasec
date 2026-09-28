-- Fixture: the file is not laid out as the name it is required under. A
-- firmware image installs this as net/util.lua; the scan sees the source tree.
local M = {}

function M.run(cmd)
   os.execute(cmd)
end

return M
