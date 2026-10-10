-- The overview of a run: how many findings, how bad, which codes and which
-- files. For a tree that produces hundreds of findings the full listing buries
-- the few that matter; this is the one screen that says where to look first.
local codes = require "luadoctor.rules.codes"
local plain = require "luadoctor.report.plain"
local sanitize = require("luadoctor.util.util").sanitize

local summary = {}

local TOP_FILES = 10

local function plural(count, word)
   return ("%d %s%s"):format(count, word, count == 1 and "" or "s")
end

-- "critical 2, high 5": the non-zero counts of `field`, in `order`.
local function tally(list, field, order)
   local counts = {}
   for _, finding in ipairs(list) do
      counts[finding[field]] = (counts[finding[field]] or 0) + 1
   end
   local parts = {}
   for _, name in ipairs(order) do
      if counts[name] then parts[#parts + 1] = name .. " " .. counts[name] end
   end
   return table.concat(parts, ", ")
end

summary.tally = tally

--- Render the overview of a normalized findings list.
function summary.render(list)
   local by_code, by_file, files = {}, {}, 0
   for _, finding in ipairs(list) do
      by_code[finding.code] = (by_code[finding.code] or 0) + 1
      if not by_file[finding.file] then files = files + 1 end
      by_file[finding.file] = (by_file[finding.file] or 0) + 1
   end

   local out = {("Summary: %s in %s"):format(plural(#list, "finding"), plural(files, "file"))}
   if #list > 0 then
      out[#out + 1] = "Severity: " .. tally(list, "severity", {"critical", "high", "medium", "low"})
      out[#out + 1] = "Confidence: " .. tally(list, "confidence", {"certain", "high", "medium", "low"})

      local rows = {}
      for code, count in pairs(by_code) do rows[#rows + 1] = {code = code, count = count} end
      table.sort(rows, function(a, b)
         if a.count ~= b.count then return a.count > b.count end
         return a.code < b.code
      end)
      local width = #tostring(rows[1].count)
      out[#out + 1] = "Codes:"
      for _, row in ipairs(rows) do
         out[#out + 1] = ("  %s  %" .. width .. "d  %s"):format(row.code, row.count, codes.meaning(row.code))
      end

      local ranked = {}
      for file, count in pairs(by_file) do ranked[#ranked + 1] = {file = file, count = count} end
      table.sort(ranked, function(a, b)
         if a.count ~= b.count then return a.count > b.count end
         return a.file < b.file
      end)
      local top_width = #tostring(ranked[1].count)
      out[#out + 1] = "Files with the most findings:"
      for index = 1, math.min(TOP_FILES, #ranked) do
         out[#out + 1] = ("  %" .. top_width .. "d  %s"):format(ranked[index].count, sanitize(ranked[index].file))
      end
   end
   out[#out + 1] = plain.score_line(list)
   return table.concat(out, "\n")
end

return summary
