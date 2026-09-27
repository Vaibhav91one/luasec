local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luasec.api"

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

describe("taint analysis: command execution", function()
   it("reports an HTTP parameter concatenated into os.execute as 709 critical", function()
      local report = api.check_source([[
local function status(host)
   os.execute("ping -c1 " .. http.formvalue(host))
end
]])
      assert_equal(codes(report), "709", "expected exactly one 709 finding")
      local finding = report[1]
      assert_equal(finding.severity, "critical")
      assert_equal(finding.name, "os.execute")
      assert_equal(finding.line, 2, "the os.execute call is on the second line of the fixture")
   end)
end)
