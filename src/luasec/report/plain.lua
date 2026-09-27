-- Human readable report.
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

   return table.concat(buffer, "\n")
end

return plain
