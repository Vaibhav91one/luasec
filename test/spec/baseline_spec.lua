-- Baseline mode. The point of a baseline is to answer one question: what is new
-- since the last time somebody looked. A finding that was already in the
-- baseline is not reported, one that is not in it is, and one that was in it and
-- is no longer found is reported as fixed, because a finding that quietly went
-- away is the other half of the question.
--
-- The unit of comparison is a finding's fingerprint, which is its code, its name
-- and its file. It deliberately has no line number in it: a statement that moved
-- down the file is the same finding, and reporting it again every time somebody
-- inserts a comment above it trains people to ignore the report.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_false = harness.assert_equal, harness.assert_true, harness.assert_false
local assert_match, assert_no_match = harness.assert_match, harness.assert_no_match

local tmp = os.tmpname()

local function write(contents)
   local handle = assert(io.open(tmp, "wb"))
   handle:write(contents)
   handle:close()
end

local function remove()
   os.remove(tmp)
end

-- One file, rewritten between runs, so the path stays the same and only the
-- source changes. A baseline compared across two paths would be comparing two
-- different files.
local VULNERABLE = [[
local function handler(request)
   local host = http.formvalue(request, "host")
   os.execute("ping -c1 " .. host)
end

return handler
]]

local FIXED = [[
local function handler(request)
   local host = http.formvalue(request, "host")
   print("ping -c1 " .. host)
end

return handler
]]

describe("--baseline", function()
   it("reports nothing for a finding the baseline already has, and exits 0", function()
      write(VULNERABLE)
      local _, write_code = harness.cli({"--format", "json", "-o", tmp .. ".json", tmp})
      assert_equal(write_code, 1, "the vulnerable file is a critical finding, so the first run fails")

      local out, code = harness.cli({"--format", "json", "--baseline", tmp .. ".json", tmp})
      assert_equal(code, 0, "no new finding, so the gate passes: " .. out)
      assert_no_match(out, "709", "a finding already in the baseline is not new: " .. out)

      os.remove(tmp .. ".json")
      remove()
   end)

   it("reports a finding the baseline does not have, and exits 3", function()
      write(FIXED)
      local _, write_code = harness.cli({"--format", "json", "-o", tmp .. ".json", tmp})
      assert_equal(write_code, 0, "the fixed file is clean, so the baseline is empty: " .. write_code)

      write(VULNERABLE)
      local out, code = harness.cli({"--format", "json", "--baseline", tmp .. ".json", tmp})
      assert_equal(code, 3, "a new critical finding must fail the gate with 3: " .. out)
      assert_match(out, "709", out)
      assert_match(out, '"new"', "the finding must be marked new: " .. out)

      os.remove(tmp .. ".json")
      remove()
   end)

   it("reports a finding that was in the baseline and is gone as fixed", function()
      write(VULNERABLE)
      local _, write_code = harness.cli({"--format", "json", "-o", tmp .. ".json", tmp})
      assert_equal(write_code, 1, write_code)

      write(FIXED)
      local out, code = harness.cli({"--format", "json", "--baseline", tmp .. ".json", tmp})
      assert_equal(code, 0, "a fixed finding is not a new one, so the gate passes: " .. out)
      assert_match(out, '"fixed"', "the finding must be reported as fixed: " .. out)
      assert_match(out, "709", out)

      os.remove(tmp .. ".json")
      remove()
   end)

   it("does not call a finding new just because the statement moved down the file", function()
      write(VULNERABLE)
      harness.cli({"--format", "json", "-o", tmp .. ".json", tmp})

      write("-- a comment inserted above the function\n" .. VULNERABLE)
      local out, code = harness.cli({"--format", "json", "--baseline", tmp .. ".json", tmp})
      assert_equal(code, 0, "a moved statement is the same finding, so nothing is new: " .. out)
      assert_no_match(out, '"new"', "the moved finding was reported as new: " .. out)

      os.remove(tmp .. ".json")
      remove()
   end)

   it("calls a finding new when the code changed, even at the same place", function()
      -- A constant command is a different finding: 701 says the argument is not
      -- a constant, 709 says untrusted data reached it. The name and the file
      -- are the same and the line barely moves.
      write([[
local function handler(request)
   local host = http.formvalue(request, "host")
   print(host)
end

return handler
]])
      harness.cli({"--format", "json", "-o", tmp .. ".json", tmp})

      write(VULNERABLE)
      local out, code = harness.cli({"--format", "json", "--baseline", tmp .. ".json", tmp})
      assert_equal(code, 3, "a new code at a known place is still new: " .. out)
      assert_match(out, "709", out)

      os.remove(tmp .. ".json")
      remove()
   end)

   it("exits 2 rather than reporting a clean run when the baseline is not a report", function()
      write(VULNERABLE)
      write("this is not json at all")

      local out, code = harness.cli({"--format", "json", "--baseline", tmp, tmp})
      assert_equal(code, 2, "an unreadable baseline is an operator error, not a clean run")
      assert_match(out, "baseline", out)

      remove()
   end)

   it("exits 2 when the baseline file does not exist", function()
      write(VULNERABLE)
      local out, code = harness.cli({"--format", "json", "--baseline", tmp .. ".absent", tmp})
      assert_equal(code, 2)
      assert_match(out, "baseline", out)
      remove()
   end)

   it("keeps the ordinary exit codes when no baseline is given", function()
      write(VULNERABLE)
      local _, clean = harness.cli({tmp})
      assert_equal(clean, 1, "a finding above the threshold is still 1 without a baseline")

      write(FIXED)
      local _, quiet = harness.cli({tmp})
      assert_equal(quiet, 0, "a clean run is still 0 without a baseline")

      local _, broken = harness.cli({"--format", "nonsense", tmp})
      assert_equal(broken, 0, "an unknown format falls back to plain, which is not an error")

      local _, missing = harness.cli({tmp .. ".absent"})
      assert_equal(missing, 2, "a file that does not exist is still 2")

      remove()
   end)

   it("marks a fixed finding as fixed in the html report and does not fail on it", function()
      write(VULNERABLE)
      harness.cli({"--format", "json", "-o", tmp .. ".json", tmp})

      write(FIXED)
      local out, code = harness.cli({"--format", "html", "--baseline", tmp .. ".json", tmp})
      assert_equal(code, 0, "a fixed finding is not a new one: " .. out)
      assert_match(out, "fixed", out, "the html report must say the finding is fixed")
      assert_match(out, "709", out, "the fixed finding must still be shown")

      os.remove(tmp .. ".json")
      remove()
   end)

   it("reads back a report this tool wrote, so a baseline can be regenerated", function()
      -- The chain a CI job actually runs: record a plain report, compare against
      -- it, and the plain report of a later run replaces it. The baseline is a
      -- plain `--format json` report, not the output of a baseline run: a
      -- baseline run reports only what changed, so feeding its output back in
      -- would forget everything it did not report. Verified by feeding the
      -- written file back in, not by reading its bytes: a file this tool cannot
      -- use as a baseline is not a baseline, whatever it looks like.
      write(VULNERABLE)
      harness.cli({"--format", "json", "-o", tmp .. ".base.json", tmp})

      local _, compared = harness.cli({"--format", "json", "--baseline", tmp .. ".base.json", tmp})
      assert_equal(compared, 0, "nothing is new against a baseline of the same file")

      write(FIXED)
      local _, refreshed = harness.cli({"--format", "json", "-o", tmp .. ".base.json", tmp})
      assert_equal(refreshed, 0, "the fixed file is clean, so the refreshed baseline is empty")

      write(VULNERABLE)
      local out, code = harness.cli({"--format", "json", "--baseline", tmp .. ".base.json", tmp})
      assert_equal(code, 3, "the vulnerability is back, so the refreshed baseline must not hide it")
      assert_match(out, "709", out)

      os.remove(tmp .. ".base.json")
      remove()
   end)

   it("documents the baseline exit code in --help", function()
      local out, code = harness.cli({"--help"})
      assert_equal(code, 0, out)
      assert_match(out, "%-%-baseline", out)
      assert_match(out, "3", "the help must say what exit 3 means: " .. out)
   end)
end)
