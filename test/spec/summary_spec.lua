local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_true

local TAINTED = "test/fixtures/tainted_exec/handler.lua"

describe("--summary", function()
   it("prints counts instead of findings", function()
      local out, code = harness.cli({"--summary", TAINTED})
      assert_equal(code, 1, out)
      assert_match(out, "Summary: 1 finding in 1 file\n", out)
      assert_match(out, "Severity: critical 1\n", out)
      assert_match(out, "Confidence: certain 1\n", out)
      assert_match(out, "\n  709  1  untrusted data reaches command execution\n", out)
      assert_match(out, "Files with the most findings:\n  1  " .. TAINTED:gsub("%p", "%%%0") .. "\n", out)
      assert_match(out, "Score: 75/100 %(needs work%) %- exec 1", out)
      assert_true(not out:find("[709] critical", 1, true), "no per-finding line: " .. out)
   end)

   it("says so plainly for a clean file", function()
      local out, code = harness.cli({"--summary", "test/fixtures/clean/report.lua"})
      assert_equal(code, 0, out)
      assert_match(out, "Summary: 0 findings in 0 files\n", out)
      assert_match(out, "Score: 100/100 %(good%)", out)
   end)

   it("works only with the plain format", function()
      local out, code = harness.cli({"--summary", "--format", "json", TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "%-%-summary works with the plain format", out)
   end)
end)

describe("the large-run hint", function()
   local function tree(count)
      local dir = harness.scratch_dir("summary_hint")
      for i = 1, count do
         local handle = assert(io.open(("%s/f%03d.lua"):format(dir, i), "w"))
         handle:write("os.execute(arg[1])\n")
         handle:close()
      end
      return dir
   end

   it("appears after more than 100 findings and counts the low-confidence ones", function()
      local dir = tree(101)
      local out = harness.cli({dir})
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_match(out, "\nHint: 101 findings, %d+ at low confidence; %-%-min%-confidence medium hides those, %-%-summary shows an overview%.\n*$", out)
   end)

   it("does not appear for a small run", function()
      local dir = tree(3)
      local out = harness.cli({dir})
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_true(not out:find("Hint:", 1, true), out)
   end)
end)
