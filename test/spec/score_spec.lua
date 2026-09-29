local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true, assert_equal = harness.assert_true, harness.assert_equal

local api = require "luasec.api"

local CATEGORIES = {exec = true, firmware = true, payload = true, artifact = true, meta = true}

describe("health score", function()
   it("is 100 with every category at zero for a clean source", function()
      local result = api.score(api.check_source("local x = 1\nreturn x\n"))
      assert_equal(result.score, 100, "no finding costs nothing")
      assert_equal(result.label, "good", "100 is good")
      for id in pairs(CATEGORIES) do
         assert_equal(result.categories[id], 0, id .. " starts at zero")
      end
   end)

   it("costs a critical finding 25 points scaled by confidence, and counts it under exec", function()
      local result = api.score(api.check_source("os.execute(io.read())\n"))
      assert_equal(result.score, 85, "one 709 from io.read, at medium confidence, is 100 - 25 * 0.6")
      assert_equal(result.label, "needs work", "85 needs work")
      assert_equal(result.categories.exec, 1, "709 is an exec finding")
   end)

   it("scales the cost by confidence", function()
      local result = api.score({{code = "701", severity = "high", confidence = "low"}})
      assert_equal(result.score, 97, "high at low confidence costs 10 * 0.3")
   end)

   it("does not charge a finding a baseline marked fixed", function()
      local result = api.score({{code = "709", severity = "critical", confidence = "high",
         status = "fixed"}})
      assert_equal(result.score, 100, "a fixed finding is good news")
      assert_equal(result.categories.exec, 0, "and is not counted")
   end)

   it("never goes below zero", function()
      local list = {}
      for i = 1, 5 do
         list[i] = {code = "709", severity = "critical", confidence = "certain"}
      end
      local result = api.score(list)
      assert_equal(result.score, 0, "five criticals floor at 0")
      assert_equal(result.label, "critical", "0 is critical")
   end)
end)

describe("rule categories", function()
   it("gives every registered code one of the five categories", function()
      for _, rule in ipairs(api.rule_catalogue()) do
         assert_true(CATEGORIES[rule.category],
            "code " .. rule.code .. " has no category (got " .. tostring(rule.category) .. ")")
      end
   end)

   it("files each code under the section docs/rules.md puts it in", function()
      local expected = {["012"] = "meta", ["709"] = "exec", ["721"] = "firmware",
         ["750"] = "payload", ["801"] = "artifact", ["901"] = "meta"}
      local seen = {}
      for _, rule in ipairs(api.rule_catalogue()) do seen[rule.code] = rule.category end
      for code, category in pairs(expected) do
         assert_equal(seen[code], category, "code " .. code)
      end
   end)
end)
