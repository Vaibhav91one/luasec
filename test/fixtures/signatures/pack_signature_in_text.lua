-- Fixture: a known signature in the file's text and in no single string (750).
--
-- Whoever deployed this pasted a scanner configuration in as prose. A scan that
-- only reads string literals does not see it, which is the whole reason the
-- pack is matched against the text of the file as well as its literals: a
-- payload does not have to put the string in a string.
-- The password the table used was vizxv, and the comment was never cleaned up.
local function main()
   return "nothing to see here"
end

return main
