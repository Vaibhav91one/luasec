local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true, assert_equal = harness.assert_true, harness.assert_equal

local api = require "luadoctor.api"

describe("rule catalogue", function()
   it("documents every registered code in docs/rules.md", function()
      local handle = assert(io.open("docs/rules.md", "r"))
      local docs = handle:read("*a")
      handle:close()

      for _, rule in ipairs(api.rule_catalogue()) do
         assert_true(docs:find(rule.code, 1, true),
            "code " .. rule.code .. " is registered but not documented in docs/rules.md")
      end
   end)

   it("gives every code a severity and a message", function()
      for _, rule in ipairs(api.rule_catalogue()) do
         assert_true(rule.severity, "code " .. rule.code .. " has no severity")
         assert_true(rule.message, "code " .. rule.code .. " has no message")
      end
   end)

   it("does not reuse codes that belong to luacheck", function()
      local reserved = {}
      for _, code in ipairs({"011", "021", "022", "023", "033", "561", "631"}) do
         reserved[code] = true
      end
      for _, rule in ipairs(api.rule_catalogue()) do
         assert_true(not reserved[rule.code], "code " .. rule.code .. " collides with luacheck")
      end
   end)

   it("sorts the catalogue by code so documentation is stable", function()
      local previous = ""
      for _, rule in ipairs(api.rule_catalogue()) do
         assert_true(rule.code > previous, "catalogue is not sorted at " .. rule.code)
         previous = rule.code
      end
      assert_true(#api.rule_catalogue() > 20, "expected the full catalogue, not a stub")
   end)
end)
