-- In-source directives: `-- luasec: ignore 709`, the way a developer silences a
-- finding they have accepted.
--
-- A directive applies from its own line to the end of the enclosing file, and a
-- `push`/`pop` pair scopes one to a region. A malformed directive is reported
-- as 021 rather than silently dropped, because a typo that looks like a
-- suppression is worse than no suppression at all.
local directives = {}

local KNOWN = {ignore = true, enable = true, only = true, push = true, pop = true}

--- Parse every `luasec:` directive in a file.
-- Returns a list of {line, action, patterns, push} and a list of problems
-- {line, message}.
function directives.parse(chstate)
   local found, problems = {}, {}

   for _, comment in ipairs(chstate.comments or {}) do
      local line = comment.line or 1
      -- `contents` is the comment text without the leading dashes.
      local body = comment.contents and
         comment.contents:match("^%s*luasec:%s*(.-)%s*$")

      if body and body ~= "" then
         local action, rest = body:match("^(%a+)%s*(.*)$")
         action = action and action:lower() or nil

         if not action or not KNOWN[action] then
            problems[#problems + 1] = {line = line,
               message = ("unknown luasec directive '%s'"):format(action or body)}
         elseif action == "push" or action == "pop" then
            found[#found + 1] = {line = line, action = action, patterns = {}}
         else
            local patterns = {}
            for pattern in rest:gmatch("[^,%s]+") do
               patterns[#patterns + 1] = pattern
            end
            if #patterns == 0 then
               problems[#problems + 1] = {line = line,
                  message = ("luasec directive '%s' needs at least one code pattern"):format(action)}
            else
               found[#found + 1] = {line = line, action = action, patterns = patterns,
                  push = rest:match("%[push%]") ~= nil}
            end
         end
      end
   end

   return found, problems
end

--- Does a finding survive the directives that apply at its line?
-- `finding.line` is compared against the directive's line, so a directive on the
-- line above a statement governs that statement.
function directives.allows(directives_before, finding, is_suppressed)
   local suppressed_by = is_suppressed
   local enabled = false

   for _, directive in ipairs(directives_before) do
      if directive.action == "ignore" then
         if directives.matches_any(directive.patterns, finding) then suppressed_by = true end
      elseif directive.action == "enable" then
         if directives.matches_any(directive.patterns, finding) then enabled = true end
      elseif directive.action == "only" then
         if directives.matches_any(directive.patterns, finding) then enabled = true
         else suppressed_by = true end
      end
   end

   return (not suppressed_by) or enabled
end

function directives.matches_any(patterns, finding)
   for _, pattern in ipairs(patterns) do
      if directives.code_and_name_match(pattern, finding) then return true end
   end
   return false
end

-- A pattern is a code, optionally with a name after a colon, and may use a
-- character class: "7", "[1234]", "70[0-9]".
function directives.code_and_name_match(pattern, finding)
   local code_pattern, name_pattern = pattern:match("^([^:]*):(.*)$")
   if not code_pattern then
      code_pattern = pattern
      name_pattern = nil
   end

   if code_pattern ~= "" and not finding.code:match("^" .. code_pattern .. "$")
         and not finding.code:match(code_pattern) then
      return false
   end

   if name_pattern and name_pattern ~= "" then
      if not finding.name or not finding.name:match(name_pattern) then
         return false
      end
   end

   return true
end

return directives
