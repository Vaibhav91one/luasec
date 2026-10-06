-- Acceptance spec for #287 (manager-authored; the worker must make it pass WITHOUT editing it).
--
-- A 709 whose tainted parts are all shell-quoted still reports the data flow, but it no longer
-- claims the certainty of an unquoted injection: it drops exactly one confidence step
-- (certain -> high), the same discount a partial filter already earns. A flow that still has an
-- unquoted tainted part is unchanged. The severity does not move.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal = harness.assert_equal

local api = require "luasec.api"

local function nine_oh_nine(report)
   for _, finding in ipairs(report) do
      if finding.code == "709" then return finding end
   end
   return nil
end

describe("709 confidence when the tainted part is shell-quoted (#287)", function()
   it("drops one step to high for a wholly shell-quoted flow, and still names the sanitizer", function()
      local report = api.check_source([[
local function go(host)
   os.execute("ping " .. luci.util.shellquote(http.formvalue("host")))
end
]], {std = "luci"})
      local finding = nine_oh_nine(report)
      assert_equal(finding ~= nil, true, "the quoted flow must still be reported")
      assert_equal(finding.confidence, "high", "one step below certain")
      assert_equal(finding.sanitizer, "shell-quoted", "the finding keeps saying why it was discounted")
      assert_equal(finding.severity, "critical", "the severity does not move")
   end)

   it("stays certain for a wholly unquoted flow", function()
      local report = api.check_source([[
local function go(host)
   os.execute("ping -c1 " .. http.formvalue("host"))
end
]])
      local finding = nine_oh_nine(report)
      assert_equal(finding ~= nil, true)
      assert_equal(finding.confidence, "certain")
      assert_equal(finding.sanitizer, nil)
   end)

   it("stays certain when one request parameter is quoted and another is not", function()
      local report = api.check_source([[
local function go(prefix, rest)
   os.execute(luci.util.shellquote(http.formvalue("prefix")) .. " " .. http.formvalue("rest"))
end
]], {std = "luci"})
      local finding = nine_oh_nine(report)
      assert_equal(finding ~= nil, true)
      assert_equal(finding.confidence, "certain", "the unquoted part is still an injection")
   end)
end)

describe("the quoted discount is only for a shell sink (#287)", function()
   it("does not downgrade a quoted value that reaches loadstring", function()
      local report = api.check_source([[
local function go()
   loadstring(luci.util.shellquote(luci.http.formvalue("c")))()
end
]], {std = "luci"})
      local found
      for _, finding in ipairs(report) do
         if finding.code == "710" then found = finding end
      end
      assert_equal(found ~= nil, true, "the code-execution flow must still be reported")
      assert_equal(found.confidence, "certain", "shell quoting does nothing for code execution")
   end)

   it("a partly quoted command is also reported as 712", function()
      local report = api.check_source([[
local function go(prefix, rest)
   os.execute(luci.util.shellquote(http.formvalue("prefix")) .. " " .. http.formvalue("rest"))
end
]], {std = "luci"})
      local has_712 = false
      for _, finding in ipairs(report) do
         if finding.code == "712" then has_712 = true end
      end
      assert_equal(has_712, true, "the unquoted part earns its own 712")
   end)
end)
