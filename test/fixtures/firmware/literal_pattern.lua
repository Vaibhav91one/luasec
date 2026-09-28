-- Patterns fixed in the source, plus a plain find that is not a pattern at all.
local function fixed(subject)
   return string.gsub(subject, "^%s+", ""),
          string.find(subject, "%d+"),
          string.match(subject, "(%a+)$"),
          ngx.re.gsub(subject, "\\d+", "x"),
          string.find(subject, pattern, 1, true)
end

return fixed
