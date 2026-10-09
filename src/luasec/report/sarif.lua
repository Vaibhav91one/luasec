-- SARIF 2.1.0. Taint findings carry a real codeFlows thread flow, so a code
-- scanning UI can show the source-to-sink path rather than just a location.
--
-- What the schema requires, and what a hand-rolled emitter gets wrong:
--   * `$schema` and `version` at the top level, and a non-empty `runs`;
--   * one `run`, whose `tool.driver` names the rules. A result may only name a
--     `ruleId` that is in `driver.rules`, so every registered code has to be
--     there or a consumer cannot resolve the finding;
--   * a thread flow location is an object wrapping `location`, carrying
--     `executionOrder`. It is not a bare location, and `executionOrder` is what
--     makes the steps a path rather than a set;
--   * a physical location names a file. There is no "unknown file" in the
--     schema, so a location without a uri is not a location;
--   * where the schema says string, `null` is not a string. An absent optional
--     key is fine; a key present with a null value is not.
local contract = require "luasec.report.findings"
local codes = require "luasec.rules.codes"
local json = require "luasec.report.json"
local version = require "luasec.version"
local score = require "luasec.report.score"
local categories = require "luasec.rules.categories"

local sarif = {}

local SARIF_LEVEL = {critical = "error", high = "error", medium = "warning", low = "note", info = "note"}

-- The doctor/1 mapping, with no confidence adjustment: critical and high are errors.
local function level_for(finding)
   return SARIF_LEVEL[finding.severity] or "note"
end

function sarif.rules_table()
   local rules = {}
   for _, spec in ipairs(codes.all()) do
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

-- A step of a flow. It gets its own line, and columns taken from the sink's
-- region only when the step is the sink: the source step is somewhere else in
-- the file and quoting the sink's columns against its line is a location that
-- points at the wrong text.
local function step_region(finding, step, is_sink)
   local region = {startLine = step.line, startColumn = 1}
   if is_sink then
      region.startColumn = finding.column
      if finding.end_column then region.endColumn = finding.end_column end
   end
   return region
end

local function physical(uri, region)
   return {physicalLocation = {artifactLocation = {uri = uri}, region = region}}
end

function sarif.render(report, opts)
   opts = opts or {}
   local s = score.summarize(report or {})
   local results = {}
   local memo = {}

   for _, finding in ipairs(report) do
      -- A physical location names a file. A finding that names a directory -
      -- the aggregate gap over an image whose symlinks all resolve to nothing,
      -- a tree that hit the walk bound - names something no consumer can open,
      -- so it gets no `locations` key at all rather than one that resolves to
      -- nothing. The schema leaves `locations` optional for exactly this: the
      -- result still carries its rule, its level and its message, so a code
      -- scanning UI lists it, it simply cannot be clicked through to a file.
      local file = contract.open_file(finding, memo)
      -- An empty `file` is the other way a finding has no place, and there the
      -- old placeholder still stands: nothing in it claims to be a scanned file.
      local unnamed = finding.file == nil or finding.file == ""
      local uri = file or (unnamed and "source.lua" or nil)

      local result = {
         ruleId = finding.code,
         level = level_for(finding),
         message = {text = finding.message ~= "" and finding.message or finding.code},
         -- `doctorFinding/v1` is the finding's fingerprint (doctor/1 contract): a hash of
         -- code, name and file, with no line in it, so a statement that moved is the same
         -- finding to a code scanning UI.
         -- `primaryLocationLineHash` is deliberately NOT written: it is GitHub's own hash of
         -- the source line, GitHub computes it, and a value of ours ("709:os.execute:2")
         -- only produced an "inconsistent fingerprint" warning on every result (#311).
         partialFingerprints = {
            ["doctorFinding/v1"] = contract.fingerprint(finding),
         },
         properties = {
            severity = finding.severity,
            confidence = finding.confidence,
            category = categories.of(finding.code),
            sink = finding.sink,
            source = finding.source,
         },
      }

      if uri then
         result.locations = {{
            physicalLocation = {
               artifactLocation = {uri = uri},
               region = step_region(finding, {line = finding.line}, true),
            },
         }}
      end

      if finding.status then
         -- The schema's own vocabulary for this: a result the baseline did not
         -- have is "new", one the baseline had and the run no longer has is
         -- "absent", which a code scanning UI shows as resolved.
         result.baselineState = finding.status == "fixed" and "absent" or finding.status
      end

      if uri and finding.trace and #finding.trace > 0 then
         local locations = {}
         for order, step in ipairs(finding.trace) do
            -- `importance` is the schema's own vocabulary for which steps of a
            -- flow matter: the source and the sink are the ones a reviewer
            -- reads. A `message` here is not an option - the schema forbids
            -- extra properties on a threadFlowLocation.
            locations[#locations + 1] = {
               -- A whole-program step can be in a different file from the
               -- finding, which is reported at the sink. Render each step
               -- against its own file, or the flow points at the wrong line.
               location = physical(step.file or uri, step_region(finding, step, step.kind == "sink")),
               executionOrder = order,
               importance = step.kind == "source" and "essential"
                  or step.kind == "sink" and "important" or "unimportant",
            }
         end
         result.codeFlows = {{threadFlows = {{locations = locations}}}}
      end

      results[#results + 1] = result
   end

   return json.encode({
      ["$schema"] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version = "2.1.0",
      runs = {{
         tool = {driver = {
            name = "luasec",
            version = version.luasec,
            informationUri = "https://github.com/Vaibhav91one/luasec",
            rules = sarif.rules_table(),
         }},
         results = results,
         properties = {score = score.envelope(s)},
      }},
   })
end

return sarif
