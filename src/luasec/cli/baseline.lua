-- Baseline comparison. Given a previous run's json report, work out which
-- findings are new and which are gone.
--
-- The baseline is a previous `--json` run (a doctor/1 envelope) and the unit of
-- comparison is the finding's `fingerprint`, from report/findings.lua: a hash of
-- code, name and file, with no line number. That is the whole reason a baseline
-- is usable in practice. A line number would make every comment inserted above a
-- function look like a new finding, and a build gate that cries wolf is a build
-- gate people turn off.
--
-- A finding is one of three things:
--   new        not in the baseline - this is what the mode exists to report
--   fixed      in the baseline and no longer found - the other half of the question
--   unchanged  in the baseline and still found - not in the plain report, but
--              listed in the json envelope with baseline_state "unchanged"
--
-- Only `new` findings fail a build. A fixed finding is good news and must not
-- cost anybody a green pipeline.
local contract = require "luasec.report.findings"
local plain = require "luasec.report.plain"

local baseline = {}

--- Read a baseline report. Returns its findings keyed by fingerprint, or nil
-- plus a message an operator can act on. A baseline is not optional input: a
-- file we cannot read has to stop the run, or a mistyped path would silently
-- turn the gate off.
function baseline.read(path)
   local handle, open_error = io.open(path, "rb")
   if not handle then
      return nil, "cannot read baseline " .. path .. ": " .. tostring(open_error)
   end
   local text = handle:read("*a")
   handle:close()

   local document, read_error = contract.read_document(text)
   if not document then
      return nil, "cannot use baseline " .. path .. ": " .. tostring(read_error)
   end

   local known = {}
   for index, finding in ipairs(document.findings) do
      local fingerprint = type(finding) == "table" and finding.fingerprint
      if type(fingerprint) ~= "string" or not fingerprint:match("^%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x$") then
         return nil, ("cannot use baseline %s: finding %d has no 16 hex character fingerprint"):format(path, index)
      end
      known[fingerprint] = finding
   end

   return known
end

--- Compare a run against a baseline.
--
-- `current` is a normalized finding list. The result is only what is news: the
-- findings this run has that the baseline did not, marked new, followed by the
-- findings the baseline had and this run does not, marked fixed. A finding in
-- both is not in the result at all - the mode answers "what changed", and a
-- finding that did not change is not an answer.
--
-- Returns the list, whether any new finding is at or above the threshold, and
-- {current = every finding of this run, marked new or unchanged, fixed = the
-- fixed ones, counts = {new, unchanged, fixed}} for the json envelope and SARIF.
local degraded = require "luasec.rules.degraded"

-- A baseline entry is a doctor/1 finding; the renderers read the internal shape.
local function from_envelope(finding)
   local location = type(finding.location) == "table" and finding.location or {}
   return {
      code = finding.id, name = finding.name, file = location.ref, line = location.line,
      column = location.column, end_column = finding.end_column, severity = finding.severity,
      confidence = finding.confidence, message = finding.message, cwe = finding.cwe,
      sink = finding.sink, source = finding.source,
   }
end

function baseline.compare(current, known, threshold_rank)
   local result = {}
   local seen, new_worst, unchanged = {}, 0, 0

   for _, finding in ipairs(current) do
      local fingerprint = contract.fingerprint(finding)
      seen[fingerprint] = true

      -- A file we could not analyze is never "already known". A baseline records
      -- which findings a previous run made, and a 901 is not a finding about the
      -- code: it is the run telling you it did not read something. Suppressing
      -- it as known printed an empty report and exited non-zero, which reads as
      -- a contradiction rather than as the warning it is.
      if degraded.is_degraded(finding.code) then
         finding.status = "new"
         result[#result + 1] = finding
      elseif known[fingerprint] == nil then
         finding.status = "new"
         local rank = plain.severity_rank(finding.severity)
         if rank > new_worst then new_worst = rank end
         result[#result + 1] = finding
      else
         finding.status = "unchanged"
         unchanged = unchanged + 1
      end
   end
   local news = #result

   -- What the baseline had and this run did not. The baseline's own copy is
   -- reported, not the run's: the location it names is where the finding was,
   -- which is the only useful thing to say about one that is no longer there.
   local fixed = {}
   for fingerprint, finding in pairs(known) do
      if seen[fingerprint] == nil then
         local normalized = contract.normalize({from_envelope(finding)}, "fixed")
         fixed[#fixed + 1] = normalized[1]
      end
   end
   -- pairs() has no order; the contract's sort is what makes the output stable.
   table.sort(fixed, function(a, b)
      if a.file ~= b.file then return a.file < b.file end
      if a.line ~= b.line then return a.line < b.line end
      if a.column ~= b.column then return a.column < b.column end
      return tostring(a.code) < tostring(b.code)
   end)
   for _, finding in ipairs(fixed) do
      result[#result + 1] = finding
   end

   local exceeded = threshold_rank ~= nil and new_worst > 0 and new_worst >= threshold_rank
   return result, exceeded, {current = current, fixed = fixed,
      counts = {new = news, unchanged = unchanged, fixed = #fixed}}
end

return baseline
