-- Human readable report.
local score = require "luasec.report.score"
local categories = require "luasec.rules.categories"
local plain = {}

local SEVERITY_ORDER = {low = 1, medium = 2, high = 3, critical = 4}

function plain.severity_rank(severity)
   return SEVERITY_ORDER[severity] or 0
end

local function location(finding, opts)
   local location = (finding.file or "<source>") .. ":" .. tostring(finding.line) .. ":" .. tostring(finding.column)
   if opts.ranges then
      location = location .. "-" .. tostring(finding.end_column)
   end
   return location
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

   for _, finding in ipairs(report) do
      local text = location(finding, opts) .. ": "
      text = text .. string.format("[%s] %s: %s", finding.code, finding.severity, finding.message or "")
      if finding.cwe and finding.cwe ~= "CWE-0" then
         text = text .. " (" .. finding.cwe .. ")"
      end
      if finding.source then
         text = text .. " [source: " .. finding.source .. "]"
      end
      if finding.sanitizer then
         text = text .. " [through " .. finding.sanitizer .. "]"
      end
      if finding.exposed_as then
         text = text .. " [exposed as " .. finding.exposed_as .. "]"
      end
      if finding.snippet then
         text = text .. "\n    " .. finding.snippet
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
