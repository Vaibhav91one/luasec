-- Fixture: the loader's argument is produced by a call this file does not
-- define. Nothing here binds `section_body`, so there is no definition in
-- either direction to follow and the chain behind the call is not readable
-- here. 741 must still fire: this is the negative that keeps the rule from
-- being deleted rather than corrected.

local function from_another_file(section)
   return loadstring(section_body(section))
end

local function through_a_concatenation(section)
   return loadstring(prefix .. section)
end

return {
   from_another_file = from_another_file,
   through_a_concatenation = through_a_concatenation,
}