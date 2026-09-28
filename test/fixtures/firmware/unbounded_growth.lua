-- Loops whose turn count the source does not state. Each keeps a string or a
-- table growing once per turn, and none of the four ceilings is visible: not
-- the limit, not the iterator, not the condition.
local function collect(n, feed)
   local s = ""
   for i = 1, tonumber(n) do
      s = s .. "x"
   end
   while n > 0 do
      s = s .. s
      n = n - 1
   end
   local t = {}
   for value in feed() do
      table.insert(t, value)
   end
   repeat
      t[#t + 1] = n
   until false
   return s, t
end

return collect
