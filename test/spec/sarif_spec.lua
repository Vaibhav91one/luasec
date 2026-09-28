local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match, assert_no_match = harness.assert_equal, harness.assert_true, harness.assert_match, harness.assert_no_match

describe("SARIF report", function()
   it("declares the SARIF 2.1.0 schema at the key the schema uses", function()
      local out = harness.cli({ "--format", "sarif", "test/fixtures/tainted_exec/handler.lua" })
      assert_match(out, '"%$schema": "https://raw%.githubusercontent%.com/oasis%-tcs/sarif%-spec', out)
      assert_no_match(out, '"schema"', "the top level key must be $schema, not schema")
   end)

   it("gives a taint finding a code flow with ordered steps", function()
      local out = harness.cli({ "--format", "sarif", "test/fixtures/tainted_exec/handler.lua" })
      assert_match(out, '"codeFlows"', out)
      assert_match(out, '"threadFlows"', out)
      assert_match(out, '"executionOrder"', "SARIF requires executionOrder on thread flow locations")
      assert_match(out, '"location"', "a thread flow location wraps a location object")
   end)

   it("lists a rule for every code the catalogue defines", function()
      local out = harness.cli({ "--format", "sarif", "test/fixtures/clean/report.lua" })
      local api = require "luasec.api"
      local _, reported = out:gsub('"id": "', "")
      assert_true(#api.rule_catalogue() > 20, "the catalogue should be populated")
      assert_equal(reported, #api.rule_catalogue(),
         "an editor needs one SARIF rule per registered code")
   end)
end)

describe("a SARIF flow that crosses a file", function()
   it("renders each step against the file that step is in", function()
      -- The flow starts in the handler and ends in the module it requires. A
      -- consumer that draws every step against the finding's own file sends the
      -- reader to the sink twice and to the source never, which is worse than
      -- publishing no flow at all.
      local out = harness.cli({ "--format", "sarif", "--whole-program", "--std", "+luci",
         "test/fixtures/whole_program/cross_file" })
      assert_match(out, '"codeFlows"', out)

      -- Each location prints its artifact URI and then the region it points at,
      -- so a uri followed by a line number is one step of the flow.
      assert_match(out,
         '"uri":%s*"[^"]*handler%.lua".-"startLine":%s*5',
         "the source step is located in the handler:\n" .. out)
      assert_match(out,
         '"uri":%s*"[^"]*util%.lua".-"startLine":%s*5',
         "the sink step is located in the required module:\n" .. out)
   end)
end)
