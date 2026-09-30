local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match = harness.assert_equal, harness.assert_match

describe("score line", function()
   it("ends a plain report with the score and the categories that have findings", function()
      local out, code = harness.cli({"test/fixtures/tainted_exec/handler.lua"})
      out = out:gsub("\n+$", "\n")
      assert_equal(code, 1, out)
      assert_match(out, "Total: 1 finding %(1 critical%)\nScore: 75/100 %(needs work%) %- exec 1\n?$", out)
   end)

   it("says 100 and good for a clean file", function()
      local out, code = harness.cli({"test/fixtures/clean/report.lua"})
      out = out:gsub("\n+$", "\n")
      assert_equal(code, 0, out)
      assert_match(out, "Score: 100/100 %(good%)\n?$", out)
   end)

   it("prints only the number with --score, and keeps the exit code", function()
      local out, code = harness.cli({"--score", "test/fixtures/tainted_exec/handler.lua"})
      assert_equal(code, 1, out)
      assert_equal(out:gsub("%s+$", ""), "75", out)
   end)

   it("names a firmware finding's category", function()
      local out = harness.cli({"--std", "+openwrt+luci", "test/fixtures/firmware/uci_tainted_value.lua"})
      assert_match(out, "Score: 94/100 %(good%) %- firmware 1", out)
   end)

   it("prints the score even with --quiet on a clean file", function()
      local out, code = harness.cli({"--quiet", "--score", "test/fixtures/clean/report.lua"})
      assert_equal(code, 0, out)
      assert_equal(out:gsub("%s+$", ""), "100", out)
   end)

   it("says incomplete and counts the gap when a file could not be parsed", function()
      local dir = harness.scratch_dir("score_gap")
      local handle = assert(io.open(dir .. "/broken.lua", "w"))
      handle:write("x = !\n")
      handle:close()
      local out = harness.cli({dir .. "/broken.lua"})
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_match(out, "Score: 99/100 %(incomplete, 1 coverage gap%)", out)
   end)
end)
