-- In-source directives: `-- luasec: ignore 709`, the way a developer silences a
-- finding they have accepted.
--
-- A directive applies from its own line to the end of the enclosing file, and a
-- `push`/`pop` pair scopes one to a region. A malformed directive is reported
-- as 012 rather than silently dropped, because a typo that looks like a
-- suppression is worse than no suppression at all.
local directives = {}

local KNOWN = {ignore = true, enable = true, only = true, push = true, pop = true}

--- Parse every `luasec:` directive in a file.
-- Returns a list of {line, action, patterns, push} and a list of problems
-- {line, message}.
-- Can Lua read this as a pattern at all? `string.match` raises on a malformed
-- one, and a directive in a file we did not write is never a pattern we checked.
-- A best-effort read of whether Lua can read this as a pattern.
--
-- It cannot be complete, and the reason is worth writing down: string.match and
-- string.gsub compile a pattern as they walk it, so a subject that matches early
-- never reaches the malformed part. `70(`, `70)`, `70%` and `70[0-9` pass every
-- probe tried here, and in use they raise nothing either - Lua only objects when
-- the matcher actually reaches the broken token.
--
-- That is the safe direction, and it is the property that matters: a pattern
-- that cannot match matches nothing, so a suppression written that way is a
-- no-op and the findings it meant to hide are still reported. The forms Lua does
-- reject outright are reported as 012, and a pattern that turns out to raise is
-- caught and recorded by matches_safely. A broken suppression never hides a
-- finding; at worst the operator is not told their typo did nothing.
local PATTERN_PROBE

do
   local bytes = {}
   for code = 0, 126 do bytes[#bytes + 1] = string.char(code) end
   PATTERN_PROBE = table.concat(bytes)
end

local function is_valid_pattern(pattern)
   if pcall(string.match, PATTERN_PROBE, pattern) then return true end
   -- Anchored, in case the failure only shows up with a fixed subject.
   return (pcall(string.match, PATTERN_PROBE, "^" .. pattern .. "$"))
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
                  -- Both halves of a `code:name` pattern, checked here rather
                  -- than at match time: a directive is read once, and raising
                  -- later kills the whole scan.
                  local code_half, name_half = pattern:match("^([^:]*):(.*)$")
                  if not code_half then code_half, name_half = pattern, nil end
                  if not is_valid_pattern(code_half)
                     or (name_half ~= nil and name_half ~= ""
                         and not is_valid_pattern(name_half)) then
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
         if directives.matches_any(directive.patterns, finding, directive.line) then
            suppressed_by = true
         end
      elseif directive.action == "enable" then
         if directives.matches_any(directive.patterns, finding, directive.line) then
            enabled = true
         end
      elseif directive.action == "only" then
         if directives.matches_any(directive.patterns, finding, directive.line) then
            enabled = true
         else suppressed_by = true end
      end
   end

   return (not suppressed_by) or enabled
end

function directives.matches_any(patterns, finding, directive_line)
   for _, pattern in ipairs(patterns) do
      if directives.code_and_name_match(pattern, finding, directive_line) then return true end
   end
   return false
end

-- Does `subject` match `pattern`? A malformed pattern is not a match and not an
-- error: the caller reports the unreadable directive, which is a finding about
-- the file rather than a crash in the analyzer.
-- Patterns that raised when we tried to use them, and the line they came from.
local UNREADABLE = {}

--- Patterns a directive asked for that Lua would not read, and where.
-- Reported as 012 by the caller: a suppression we could not read is not one we
-- applied, so the findings it meant to hide are still reported.
function directives.unreadable()
   local out = {}
   for line, pattern in pairs(UNREADABLE) do
      out[#out + 1] = {line = line, pattern = pattern}
   end
   table.sort(out, function(a, b) return a.line < b.line end)
   return out
end

function directives.reset_unreadable()
   for line in pairs(UNREADABLE) do UNREADABLE[line] = nil end
end

local function matches_safely(subject, pattern, line)
   local ok, result = pcall(string.match, subject, pattern)
   if ok then return result ~= nil end

   ok, result = pcall(string.match, subject, "^" .. pattern .. "$")
   if ok then return result ~= nil end

   -- This is the only reliable moment to learn a pattern is malformed: the
   -- matcher compiles as it walks, so `70(` matches "70" and returns before it
   -- reaches the unfinished capture. Any probe run beforehand calls it valid.
   if line then UNREADABLE[line] = pattern end
   return false
end

-- A pattern is a code, optionally with a name after a colon, and may use a
-- character class: "7", "[1234]", "70[0-9]".
function directives.code_and_name_match(pattern, finding, directive_line)
   local code_pattern, name_pattern = pattern:match("^([^:]*):(.*)$")
   if not code_pattern then
      code_pattern = pattern
      name_pattern = nil
   end

   -- The pattern is the operator's own text, and a file we did not write is not
   -- a pattern we validated. `-- luasec: ignore [708` is a typo, and handing it
   -- to string.match raised "malformed pattern", which killed the whole scan and
   -- discarded every other file's findings. So the match is guarded, a pattern we
   -- cannot read matches nothing, and the pattern is recorded for 012.
   if code_pattern ~= "" and not matches_safely(finding.code, code_pattern, directive_line) then
      return false
   end

   -- The name half goes through the same guard as the code half. `701:[bad` is
   -- the same typo one character later, and it raised here with the whole scan
   -- gone: one file in a tree, zero output, and every other file's findings
   -- discarded.
   if name_pattern and name_pattern ~= "" then
      if not finding.name or not matches_safely(finding.name, name_pattern, directive_line) then
         return false
      end
   end

   return true
end

return directives
