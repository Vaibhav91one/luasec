-- Fixture: no execution sink, no untrusted data.
local M = {}

function M.render(host, count)
   local parts = {}
   for i = 1, count do
      parts[i] = string.format("%s#%d", host, i)
   end
   return table.concat(parts, "\n")
end

return M
