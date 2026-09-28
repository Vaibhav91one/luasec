local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_no_match = harness.assert_equal, harness.assert_no_match


describe("a method call on a local", function()
   it("reads its arguments instead of raising", function()
      local api = require "luasec.api"
      local handle = assert(io.open("test/fixtures/method_call_on_local.lua", "r"))
      local report = api.check_source(handle:read("*a"), {std = "+luci"})
      handle:close()

      local found = 0
      for _, finding in ipairs(report) do
         if finding.code == "901" then
            found = found + 1
            assert_no_match(finding.message or "", "number value",
               "a method call is not a crash: " .. tostring(finding.message))
         end
      end
      assert_equal(found, 0,
         "a method call with arguments is valid Lua and must not be a failure")
   end)
end)
