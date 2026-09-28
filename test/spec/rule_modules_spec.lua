local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luasec.api"

describe("rule modules", function()
   it("loads every module the registry names", function()
      local ok, err = pcall(function()
         return require("luasec.rules.registry").detectors()
      end)
      assert_true(ok, "the rule registry must load: " .. tostring(err))
   end)

   it("does not change findings when a module contributes no detectors", function()
      local report = api.check_source([[
local function go(host)
   os.execute("ping " .. http.formvalue("host"))
end
]])
      assert_equal(#report, 1)
      assert_equal(report[1].code, "709")
   end)
end)
