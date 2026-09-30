local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match = harness.assert_equal, harness.assert_match

local TAINTED = "test/fixtures/tainted_exec/handler.lua"

describe("luasec why", function()
   it("explains a finding: the flow from source to sink and how to fix it", function()
      local out, code = harness.cli({"why", TAINTED .. ":3"})
      assert_equal(code, 0, out)
      assert_match(out, "%[709%] critical", out)
      assert_match(out, "\n  source  http%.formvalue  " .. TAINTED:gsub("%p", "%%%0") .. ":3\n", out)
      assert_match(out, "\n  sink    os%.execute  ", out)
      assert_match(out, "\n  how to fix:\n    Do not build a shell command from request data", out)
      assert_match(out, "\n  more: luasec rules explain 709", out)
   end)

   it("says so when nothing is reported on that line", function()
      local out, code = harness.cli({"why", TAINTED .. ":1"})
      assert_equal(code, 0, out)
      assert_match(out, "nothing reported at " .. TAINTED:gsub("%p", "%%%0") .. ":1", out)
   end)

   it("passes scan options through", function()
      local out, code = harness.cli({"why", "test/fixtures/firmware/uci_tainted_value.lua:7",
         "--std", "+openwrt+luci"})
      assert_equal(code, 0, out)
      assert_match(out, "%[722%]", out)
   end)

   it("refuses a target without a line", function()
      local out, code = harness.cli({"why", TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "why needs <file>:<line>", out)
   end)

   it("refuses a file it cannot read instead of saying nothing is reported", function()
      local out, code = harness.cli({"why", "test/fixtures/does-not-exist.lua:3"})
      assert_equal(code, 2, out)
      assert_match(out, "cannot read test/fixtures/does%-not%-exist%.lua", out)
   end)

   it("selects findings the way the scan does", function()
      local out, code = harness.cli({"why", TAINTED .. ":3", "--ignore", "709"})
      assert_equal(code, 0, out)
      assert_match(out, "nothing reported at", out)
      out = harness.cli({"why", TAINTED .. ":3", "--only", "701"})
      assert_match(out, "nothing reported at", out)
      out = harness.cli({"why", TAINTED .. ":3", "--min-confidence", "certain"})
      assert_match(out, "%[709%]", "a certain 709 passes a certain floor: " .. out)
   end)

   it("applies the config file", function()
      local dir = harness.scratch_dir("why_config")
      local handle = assert(io.open(dir .. "/c.lua", "w"))
      handle:write("return {disable = {'709'}}")
      handle:close()
      local out = harness.cli({"why", TAINTED .. ":3", "--config", dir .. "/c.lua"})
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_match(out, "nothing reported at", out)
   end)
end)
