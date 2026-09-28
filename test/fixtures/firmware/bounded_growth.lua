-- The same accumulator shapes with a ceiling the source states: 64 and 10
-- turns, one turn per element of a container, one per line, and one append
-- outside any loop at all.
local function fixed(label, t, handle)
   local s = ""
   for i = 1, 64 do
      s = s .. "x"
   end
   local out = {}
   for i = 1, 10, 2 do
      table.insert(out, i)
   end
   for key, value in pairs(t) do
      out[#out + 1] = value
   end
   for line in handle:lines() do
      out[#out + 1] = line
   end
   s = s .. label
   return s, out
end

return fixed
