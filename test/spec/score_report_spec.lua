local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal = harness.assert_equal

local api = require "luasec.api"

local TAINTED = "test/fixtures/tainted_exec/handler.lua"

local function decode(text)
   -- the report module ships its own reader for the documents it writes
   local findings = require "luasec.report.findings"
   return findings.decode(text)
end

describe("score in machine-readable reports", function()
   it("puts the score, label and category counts at the top of the JSON document", function()
      local doc = decode(api.format(api.analyze({TAINTED}, {}), "json"))
      assert_equal(doc.score.value, 75, "one certain 709")
      assert_equal(doc.score.label, "needs work", "75")
      assert_equal(doc.score.categories.exec, 1, "the 709")
      assert_equal(doc.score.categories.firmware, 0, "nothing else")
      assert_equal(#doc.findings, 1, "findings unchanged")
      assert_equal(doc.findings[1].category, nil, "a finding carries no new field")
   end)

   it("puts the score in the SARIF run and the category in each result", function()
      local doc = decode(api.format(api.analyze({TAINTED}, {}), "sarif"))
      local run = doc.runs[1]
      assert_equal(run.properties.score.value, 75, "run score")
      assert_equal(run.properties.score.label, "needs work", "run label")
      assert_equal(run.results[1].properties.category, "exec", "709 is exec")
   end)

   it("carries the coverage gap count in JSON and SARIF", function()
      local doc = decode(api.format(api.analyze({TAINTED}, {}), "json"))
      assert_equal(doc.score.coverage_gaps, 0, "a clean read has no gaps")
      local sarif = decode(api.format(api.analyze({TAINTED}, {}), "sarif"))
      assert_equal(sarif.runs[1].properties.score.coverage_gaps, 0, "same in SARIF")
   end)
end)
