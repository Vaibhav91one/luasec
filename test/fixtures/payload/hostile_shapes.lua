-- Fixture: shapes that would make a naive pattern or an unbounded walk slow.
--
-- 1. A very long identifier, called: the loader check must not backtrack on it.
-- 2. A local rebound thousands of times, then read: tracing a value must stop.
-- 3. A deeply nested concatenation.
-- 4. A long run of one character in a name, and a long run of a decoder-looking
--    word repeated, both as identifier fragments.
local function M()
end

M.hostile = {}

local long_name = string.rep("a", 4000) .. "!"
M.hostile[long_name .. "_decode"] = function()
end
M.hostile[long_name .. "_decode"]()

local rebound
for index = 1, 4000 do
   rebound = tostring(index)
end
loadstring(rebound)

local nested = "x"
for index = 1, 60 do
   nested = nested .. nested
end
loadstring(nested)

local alphabet = {}
for index = 1, 64 do
   alphabet[index] = string.char(65 + index)
end
loadstring(table.concat(alphabet))

return M
