-- SARIF 2.1.0. Taint findings carry a real codeFlows thread flow, so a code
-- scanning UI can show the source-to-sink path rather than just a location.
local codes = require "luasec.rules.codes"
local util = require "luasec.util.util"
local json = require "luasec.report.json"
local version = require "luasec.version"

local sarif = {}

local SARIF_LEVEL = {critical = "error", high = "error", medium = "warning", low = "note"}

local function level_for(finding)
   if finding.confidence == "low" then
      if finding.severity == "critical" or finding.severity == "high" then return "warning" end
   end
   return SARIF_LEVEL[finding.severity] or "note"
end

function sarif.rules_table()
   local seen, rules = {}, {}
   for _, spec in ipairs(codes.all()) do
      seen[spec.code] = true
      rules[#rules + 1] = {
         id = spec.code,
         name = spec.code,
         shortDescription = {text = spec.message},
         fullDescription = {text = spec.message},
         defaultConfiguration = {level = SARIF_LEVEL[spec.severity] or "note"},
         properties = {
            cwe = spec.cwe,
            severity = spec.severity,
            tags = {"security", "firmware", "lua"},
         },
      }
   end
   return rules
end

local function location_object(finding, step)
   local region = {
      startLine = finding.line,
      startColumn = finding.column,
   }
   if finding.end_column then
      region.endColumn = finding.end_column
   end
   if step and step.snippet then
      region.snippet = {text = step.snippet}
   end
   return {
      physicalLocation = {
         artifactLocation = {uri = finding.file or "source.lua"},
         region = region,
      }
   }
end

function sarif.render(report, opts)
   opts = opts or {}
   local results = {}

   for _, finding in ipairs(report) do
      local result = {
         ruleId = finding.code,
         level = level_for(finding),
         message = {text = finding.message or finding.code},
         locations = {location_object(finding)},
         partialFingerprints = {
            primaryLocationLineHash = util.fingerprint({finding.code, finding.name, finding.line}),
         },
         properties = {
            severity = finding.severity,
            confidence = finding.confidence,
            sink = finding.sink,
            source = finding.source,
         },
      }

      if finding.trace and #finding.trace > 0 then
         local locations = {}
         for _, step in ipairs(finding.trace) do
            local step_location = vim_deepcopy_location(finding, step)
            locations[#locations + 1] = step_location
         end
         result.codeFlows = {{
            threadFlows = {{
               locations = locations,
            }},
         }}
      end

      results[#results + 1] = result
   end

   local log = {
      ["$schema"] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version = "2.1.0",
      runs = {{
         tool = {
            driver = {
               name = "luasec",
               version = version.luasec,
               informationUri = "https://github.com/Vaibhav91one/luasec",
               rules = sarif.rules_table(),
            },
         },
         results = results,
      }},
   }

   return json.encode(log)
end

function vim_deepcopy_location(finding, step)
   local step_finding = {
      file = finding.file,
      line = step.line or finding.line,
      column = finding.column,
      end_column = finding.end_column,
   }
   if step.snippet then
      step_finding.snippet = step.snippet
   end
   return location_object(step_finding, step.snippet and {snippet = step.snippet} or nil)
end

return sarif
