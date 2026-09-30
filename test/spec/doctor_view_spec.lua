local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_true

local TAINTED = "test/fixtures/tainted_exec/handler.lua"
local MANY = "test/fixtures/firmware"

local function q(text) return string.format("%q", text) end

describe("the doctor view", function()
   it("groups findings under a header with the score", function()
      local out, code = harness.cli({"--view", "doctor", TAINTED})
      assert_equal(code, 1, out)
      assert_match(out, "luasec", out)
      assert_match(out, "Score 75/100  needs work  %[", out)
      assert_match(out, "1 finding in 1 file: critical 1\n", out)
      assert_match(out, "exec 1", out)
      assert_match(out, "✖ 709  untrusted data reaches command execution  critical · certain\n", out)
      assert_match(out, "\n    test/fixtures/tainted_exec/handler%.lua:3\n", out)
      assert_true(not out:find("[709] critical:", 1, true), "no flat line: " .. out)
      assert_match(out, "Next: luasec why <file>:<line>", out)
   end)

   it("shows the first three locations of a code and counts the rest", function()
      local dir = harness.scratch_dir("doctor_group")
      for i = 1, 5 do
         local handle = assert(io.open(("%s/f%d.lua"):format(dir, i), "w"))
         handle:write("os.execute(arg[1])\n")
         handle:close()
      end
      local out = harness.cli({"--view", "doctor", dir})
      local all = harness.cli({"--view", "doctor", "--verbose", dir})
      os.execute("rm -rf " .. q(dir))
      assert_match(out, "701  command execution with a non%-constant argument ×5", out)
      assert_match(out, "… and 2 more\n", out)
      assert_true(not all:find("and 2 more", 1, true), "--verbose lists every location: " .. all)
      assert_match(all, "f5%.lua:1", all)
   end)

   it("keeps the worst codes and says how many it hid", function()
      local out = harness.cli({"--view", "doctor", "--std", "+openwrt+luci", MANY})
      local all = harness.cli({"--view", "doctor", "--verbose", "--std", "+openwrt+luci", MANY})
      assert_match(out, "%d+ more codes? with %d+ findings? hidden", out)
      assert_true(not all:find("hidden", 1, true), "--verbose hides nothing: " .. all)
   end)

   it("says a clean run is clean", function()
      local out, code = harness.cli({"--view", "doctor", "test/fixtures/clean/report.lua"})
      assert_equal(code, 0, out)
      assert_match(out, "✔ No findings", out)
      assert_match(out, "Score 100/100  good", out)
   end)

   it("uses colour only when asked or on a terminal", function()
      local plain = harness.cli({"--view", "doctor", TAINTED})
      local coloured = harness.cli({"--view", "doctor", "--color", TAINTED})
      assert_true(not plain:find("\27", 1, true), "not a terminal, no colour")
      assert_match(coloured, "\27%[31m", coloured)
   end)

   it("is not the default when stdout is not a terminal, and never replaces other output", function()
      local flat = harness.cli({TAINTED})
      assert_match(flat, "%[709%] critical:", flat)
      local summary = harness.cli({"--view", "doctor", "--summary", TAINTED})
      assert_match(summary, "Summary: 1 finding", summary)
      assert_true(not summary:find("Next:", 1, true), summary)
      local score = harness.cli({"--view", "doctor", "--score", TAINTED})
      assert_equal(score:gsub("%s+$", ""), "75", score)
   end)

   it("refuses an unknown view", function()
      local out, code = harness.cli({"--view", "fancy", TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "%-%-view expects list or doctor", out)
   end)

   it("lists a place once when two findings share a line", function()
      local dir = harness.scratch_dir("doctor_dupes")
      local handle = assert(io.open(dir .. "/a.lua", "w"))
      handle:write("os.execute(arg[1]) os.execute(arg[2])\n")
      handle:close()
      local out = harness.cli({"--view", "doctor", dir})
      os.execute("rm -rf " .. q(dir))
      assert_match(out, "×2", out)
      local _, places = out:gsub("a%.lua:1\n", "")
      assert_equal(places, 1, "one place for two findings: " .. out)
      assert_true(not out:find("and 1 more", 1, true), out)
   end)
end)
