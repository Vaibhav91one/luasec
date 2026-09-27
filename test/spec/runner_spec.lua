local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

describe("test runner", function()
   it("exits with status 0 when every spec passes", function()
      local out, code = harness.run_suite({ "test/spec/passing_suite" })
      assert_equal(code, 0, "runner output:\\n" .. out)
      assert_match(out, "1 passed", "should report the passing spec")
   end)

   it("exits non-zero and names the spec when a spec fails", function()
      local out, code = harness.run_suite({ "test/selfcheck" })
      assert_true(code ~= 0, "a failing suite must not exit 0")
      assert_match(out, "fails on purpose", "should name the failing spec")
      assert_match(out, "intentional", "should surface the assertion message")
   end)
end)
