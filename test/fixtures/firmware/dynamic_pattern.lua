-- A request parameter used as a search pattern. A Lua pattern with captures
-- nested deeply, or a repetition count the caller chose, is a denial of service
-- and not a search.
local function scrub(pattern, subject)
   local out = string.gsub(subject, pattern, "")
   local hit = string.find(subject, pattern)
   local cap = string.match(subject, pattern)
   for word in string.gmatch(subject, pattern) do
      out = out .. word
   end
   out = ngx.re.gsub(subject, pattern, "x")
   local first = ngx.re.find(subject, pattern)
   return out, hit, cap, first
end

return scrub
