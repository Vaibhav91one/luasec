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
-- Can Lua read this as a pattern at all? `string.match` raises on a malformed
-- one, and a directive in a file we did not write is never a pattern we checked.
local function is_valid_pattern(pattern)
   local ok = pcall(string.match, "", pattern)
   return ok
end

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
               -- Every pattern is checked while the directive is read, so a
               -- suppression the operator cannot express is reported here rather
               -- than crashing the matcher later. It is still recorded: a
               -- suppression we could not read is not a suppression we applied.
               local unreadable = nil
               for _, pattern in ipairs(patterns) do
                  if not is_valid_pattern(pattern) then
                     unreadable = pattern
                     break
                  end
               end
               if unreadable then
                  problems[#problems + 1] = {line = line,
                     message = ("luasec directive '%s' has an unreadable code pattern '%s'")
                        :format(action, unreadable)}
               end
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

-- Does `subject` match `pattern`? A malformed pattern is not a match and not an
-- error: the caller reports the unreadable directive, which is a finding about
-- the file rather than a crash in the analyzer.
local function matches_safely(subject, pattern)
   local ok, result = pcall(string.match, subject, pattern)
   if ok then return result ~= nil end

   ok, result = pcall(string.match, subject, "^" .. pattern .. "$")
   return ok and result ~= nil
end

-- A pattern is a code, optionally with a name after a colon, and may use a
-- character class: "7", "[1234]", "70[0-9]".
function directives.code_and_name_match(pattern, finding)
   local code_pattern, name_pattern = pattern:match("^([^:]*):(.*)$")
   if not code_pattern then
      code_pattern = pattern
      name_pattern = nil
   end

   -- The pattern is the operator's own text, and a file we did not write is not
   -- a pattern we validated. `-- luasec: ignore [708` is a typo, and passing it
   -- to string.match raised "malformed pattern" - which killed the whole scan
   -- and discarded every other file's findings. A directive we cannot read is a
   -- directive we cannot honour, so it matches nothing and is reported as
   -- unreadable (021) rather than taken as an error here.
   if code_pattern ~= "" and not matches_safely(finding.code, code_pattern) then
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
