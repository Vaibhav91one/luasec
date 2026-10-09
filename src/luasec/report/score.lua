-- The 0-100 health score. It is computed around a report, never stored in one:
-- a finding's shape does not change, and the same findings always give the same
-- score. 100 means nothing was found. Each finding costs its severity weight
-- scaled by its confidence, and the score is 100 minus the total, rounded down
-- and floored at 0. A finding a baseline marked fixed costs nothing. A coverage
-- gap makes a "good" result "incomplete".
local categories = require "luasec.rules.categories"
local degraded = require "luasec.rules.degraded"

local score = {}

local WEIGHT = {critical = 25, high = 10, medium = 4, low = 1}
local CONFIDENCE = {certain = 1, high = 1, medium = 0.6, low = 0.3}

function score.penalty(finding)
   return (WEIGHT[finding.severity] or 0) * (CONFIDENCE[finding.confidence] or 1)
end

function score.label(value)
   if value >= 90 then return "good" end
   if value >= 60 then return "needs work" end
   return "critical"
end

--- Score a findings list. Returns {score, label, categories}, where
-- categories counts the findings in each category id.
function score.summarize(list)
   local total, counts = 0, {}
   local gaps = 0
   for _, id in ipairs(categories.order()) do counts[id] = 0 end
   for _, finding in ipairs(list) do
      if finding.status ~= "fixed" then
         total = total + score.penalty(finding)
         if degraded.is_degraded(finding.code) then gaps = gaps + 1 end
         local id = categories.of(finding.code)
         if id then counts[id] = counts[id] + 1 end
      end
   end
   local value = math.max(0, math.floor(100 - total))
   local label = score.label(value)
   if gaps > 0 and label == "good" then label = "incomplete" end
   return {score = value, label = label, categories = counts, coverage_gaps = gaps}
end

--- The doctor/1 score object (docs/doctor-contract.md section 3) for a summary.
-- The formula is the one above; `model` names it and changes whenever it does.
function score.envelope(summary)
   return {value = summary.score, label = summary.label, model = "luasec/1",
      coverage_gaps = summary.coverage_gaps}
end

return score
