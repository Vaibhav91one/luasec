-- Human readable report.
local contract = require "luadoctor.report.findings"
local score = require "luadoctor.report.score"
local categories = require "luadoctor.rules.categories"
local sanitize = require("luadoctor.util.util").sanitize
local plain = {}

local SEVERITY_ORDER = {low = 1, medium = 2, high = 3, critical = 4}

function plain.severity_rank(severity)
   return SEVERITY_ORDER[severity] or 0
end

-- `path:line:column`, or nil when the finding names no file a reader can open.
--
-- The finding that matters here is the one about the run rather than about a
-- place in it: the aggregate gap over an image whose symlinks all resolve to
-- nothing, a tree that hit the walk bound, a directory that would not list.
-- Those carry the scanned directory, and `dir:1:1` is formatted so that
-- `vim +{line} {file}` or an editor's "jump to location" will try to open it -
-- there is nothing there a reader can be sent to. SARIF makes the same call
-- and omits the location; printing one here would have the two formats
-- disagreeing about a finding they otherwise report identically.
local function location(finding, opts, memo)
   local file = contract.open_file(finding, memo)
   if not file then return nil end
   local place = sanitize(file) .. ":" .. tostring(finding.line) .. ":" .. tostring(finding.column)
   if opts.ranges then
      place = place .. "-" .. tostring(finding.end_column)
   end
   return place
end

--- The closing "Score: ..." line for a findings list.
function plain.score_line(report)
   -- The health score, computed from the same findings the total counts. A
   -- category with nothing in it is left out, so the line stays short.
   local summary = score.summarize(report)
   local counted = {}
   for _, id in ipairs(categories.order()) do
      if summary.categories[id] > 0 then
         counted[#counted + 1] = id .. " " .. summary.categories[id]
      end
   end
   local note = summary.coverage_gaps > 0
      and (", %d coverage gap%s"):format(summary.coverage_gaps, summary.coverage_gaps == 1 and "" or "s") or ""
   return string.format("Score: %d/100 (%s%s)%s", summary.score, summary.label, note,
      #counted > 0 and (" - " .. table.concat(counted, ", ")) or "")
end

function plain.render(report, opts)
   opts = opts or {}
   local buffer = {}
   local memo = {}

   for _, finding in ipairs(report) do
      local place = location(finding, opts, memo)
      local text = place and (place .. ": ") or ""
      text = text .. string.format("[%s] %s: %s", sanitize(finding.code),
         sanitize(finding.severity), sanitize(finding.message or ""))
      if finding.cwe and finding.cwe ~= "CWE-0" then
         text = text .. " (" .. sanitize(finding.cwe) .. ")"
      end
      if finding.source then
         text = text .. " [source: " .. sanitize(finding.source) .. "]"
      end
      if finding.sanitizer then
         text = text .. " [through " .. sanitize(finding.sanitizer) .. "]"
      end
      if finding.exposed_as then
         text = text .. " [exposed as " .. sanitize(finding.exposed_as) .. "]"
      end
      if finding.snippet then
         text = text .. "\n    " .. sanitize(finding.snippet)
      end
      buffer[#buffer + 1] = text
   end

   if #buffer > 0 then
      buffer[#buffer + 1] = ""
   end

   local counts = {}
   for _, finding in ipairs(report) do
      counts[finding.severity] = (counts[finding.severity] or 0) + 1
   end

   local parts = {}
   for _, severity in ipairs({"critical", "high", "medium", "low"}) do
      if counts[severity] then
         parts[#parts + 1] = counts[severity] .. " " .. severity
      end
   end

   buffer[#buffer + 1] = string.format("Total: %d finding%s (%s)",
      #report, #report == 1 and "" or "s", #parts > 0 and table.concat(parts, ", ") or "none")

   buffer[#buffer + 1] = plain.score_line(report)

   if #report > 100 then
      local low = 0
      for _, finding in ipairs(report) do
         if finding.confidence == "low" then low = low + 1 end
      end
      buffer[#buffer + 1] = ("Hint: %d findings, %d at low confidence; --min-confidence medium hides those, --summary shows an overview."):format(#report, low)
   end

   return table.concat(buffer, "\n")
end

return plain
