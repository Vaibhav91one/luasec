-- Fixture: a module whose field hands its argument straight back.
local M = {}

function M.id(x)
   return x
end

function M.q(s)
   return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

return M
