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
            -- Markers, not suppressions: they only open and close a region.
            found[#found + 1] = {line = line, action = action, patterns = {},
               marker = true}
         else
            -- `[push]` is a scope marker, not a code pattern. It used to be
            -- tokenized as one as well, so a self-pushing suppression also went
            -- looking for findings named "push".
            local scoped_by_itself = rest:match("%[push%]") ~= nil
            rest = rest:gsub("%[push%]", "")
            local patterns = {}
            for pattern in rest:gmatch("[^,%s]+") do
               patterns[#patterns + 1] = pattern
            end
            if #patterns == 0 or rest:match("^%s*:%s*$") then
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
                  push = scoped_by_itself}
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

   -- A `push` opens a region and a `pop` closes it. Both markers were recorded
   -- and then never read, so a pop changed nothing and a suppression between a
   -- push and a pop stayed in force to the end of the file: the operator asked
   -- for one region and got the whole file, with nothing to say so.
   --
   -- Net depth, because pushes open and pops close: counting only pushes leaves
   -- every region open for the rest of the file, which is the bug this replaced.
   -- A pop with no push is a no-op rather than a negative depth, and a `[push]`
   -- on a suppression opens a region exactly as a bare `push` line does.
   --
   -- Computed ONCE per finding into a prefix array, rather than by rescanning
   -- the directive list for every directive. Asking the list the same question
   -- once per question is O(directives) per finding per directive: a file with
   -- 2,000 suppression lines and 1,600 findings took 171 s where the build before
   -- the scoping fix took 0.9 s, and --max-nodes does not bound it because a rule
   -- that raises is caught rather than skipped. The whole thing is one pass.
   --
   -- Depth here is POSITIONAL, by index into the list, where the line-based
   -- version it replaced compared line numbers. The two differ only for an
   -- unsorted list, which the lexer cannot produce - it appends one record per
   -- comment in token order - so this is not reachable through the CLI. But
   -- `directives.allows` is exported, and a caller could hand it one; on
   -- unsorted input this version is the more suppressive of the two.
   --
   -- `depth_before[i]` is the region depth at directive i counting everything
   -- before it, so a `[push]` directive can be compared against its own base
   -- without its contribution - it governs the region above it rather than
   -- nesting inside it.
   local count = #directives_before
   local depth_before, depth_after

   if count > 0 then
      depth_before, depth_after = {}, {}
      local depth = 0
      for index, directive in ipairs(directives_before) do
         depth_before[index] = depth
         if (directive.marker and directive.action == "push")
            or (directive.push == true and directive.action ~= "pop") then
            depth = depth + 1
         elseif directive.marker and directive.action == "pop" then
            depth = math.max(0, depth - 1)
         end
         depth_after[index] = depth
      end
   end

   local open_at_finding = count > 0 and depth_after[count] or 0

   for index, directive in ipairs(directives_before) do
      if directive.action == "ignore" then
         -- A suppression written outside every region is file-wide, which is
         -- what a plain `-- luasec: ignore` has always meant. One written inside
         -- a region lives and dies with it.
         --
         -- `[push]` means this suppression opens a region of its own, and it is
         -- compared against the depth WITHOUT its own contribution: it does not
         -- nest inside a `push` line above it, it governs the region that line
         -- opened. Counting it as an extra level instead let one `pop` close
         -- only half of what was opened and left the suppression in force past
         -- the end of its region - the same fail-open shape as the pop that was
         -- never read at all.
         --
         -- Three cases, and getting them apart is the whole of the contract:
         --   written outside every region  -> file-wide, as it always meant
         --   written inside a region       -> only while that region is open
         --   carrying [push]               -> the region it opens itself, so the
         --                                    threshold is one deeper than the
         --                                    depth it was written at
         local base = depth_before[index]
         local applies
         if directive.push then
            applies = open_at_finding >= base + 1
         elseif base > 0 then
            applies = open_at_finding > 0
         else
            applies = true
         end

         if applies then
            if directives.matches_any(directive.patterns, finding, directive.line) then
               suppressed_by = true
            end
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

--- Can Lua read this as a pattern at all? Exposed so the command line can ask
-- the same question, for the same reason.
function directives.is_readable_pattern(pattern)
   return is_valid_pattern(pattern)
end

--- Cleared between files: the table is keyed by line, and a line number in one
-- file says nothing about a line number in the next.
function directives.reset_unreadable()
   for line in pairs(UNREADABLE) do UNREADABLE[line] = nil end
end

local function matches_safely(subject, pattern, line)
   local ok, result = pcall(string.match, subject, pattern)
   if ok then return result ~= nil end

   -- The first failure is the answer. Retrying anchored and taking that as the
   -- verdict was how three malformed patterns produced no 012 at all: `^70($`
   -- and `^70%$` are both legal Lua, so the retry succeeded and reported "no
   -- match" where the honest answer is "I could not read this".
   --
   -- The anchored form is still tried, because a pattern that only makes sense
   -- anchored is a legitimate way to write one; it just does not get to overrule
   -- the first failure.
   if line then UNREADABLE[line] = pattern end

   ok, result = pcall(string.match, subject, "^" .. pattern .. "$")
   if ok then return result ~= nil end
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
   -- An empty code half names no code and so matches every finding, which is
   -- not what a suppression means. `-- luasec: ignore :` is read as 012 rather
   -- than as a blanket suppression, and a plain `-- luasec: ignore` already is.
   if code_pattern == "" then return false end

   if not matches_safely(finding.code, code_pattern, directive_line) then
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
