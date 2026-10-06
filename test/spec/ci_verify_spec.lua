local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match, assert_no_match =
   harness.assert_equal, harness.assert_true, harness.assert_match, harness.assert_no_match

-- `make ci-verify` ends with `@echo "ci-verify: PASS"`, but if corpus/ is absent
-- the precision target skips its measurement and exits 0. A PASS with no
-- measurement is a false claim (#233). This spec pins the guard we added for it:
-- `ci-verify-complete`, a phony target that fails loud when corpus/ is not there,
-- and the wiring that makes ci-verify depend on it last.

local MAKEFILE = "Makefile"

-- Run `make -f <copy> ci-verify-complete` in a dir, returning output and exit code.
local function run_ci_verify_complete(dir, makefile_copy)
   local cmd = ("cd %q && make -f %q ci-verify-complete 2>&1; printf '\\n__EXIT__%%d' $?"
      ):format(dir, makefile_copy)
   local pipe = assert(io.popen(cmd))
   local out = pipe:read("*a")
   pipe:close()
   local code = tonumber(out:match("__EXIT__(%d+)%s*$") or "-1")
   return (out:gsub("__EXIT__%d+%s*$", "")), code
end

-- Read the Makefile text and find the `ci-verify:` recipe line.
local function ci_verify_line(text)
   -- Grab only the prerequisite list (the rest of the line after `ci-verify:`),
   -- stopping at the end of that line so the recipe is not pulled in.
   local line = text:match("\nci%-verify:%s*([^\n]*)")
   return line
end

describe("ci-verify-complete guard", function()
   it("fails non-zero and says INCOMPLETE without mentioning PASS when corpus/ is absent", function()
      local dir = harness.scratch_dir("ci_verify_no_corpus")
      local copy = dir .. "/Makefile"
      -- Copy the real Makefile into a fresh temp dir that has no corpus/.
      local src = assert(io.open(MAKEFILE, "r"))
      local dst = assert(io.open(copy, "w"))
      dst:write(src:read("*a"))
      src:close()
      dst:close()

      local out, code = run_ci_verify_complete(dir, copy)

      assert_true(code ~= 0,
         "ci-verify-complete exited 0 without corpus/, so ci-verify would print PASS "
         .. "on a skipped measurement:\n" .. out)
      assert_match(out, "INCOMPLETE",
         "the failure does not say the measurement was skipped:\n" .. out)
      assert_match(out, "precision was skipped",
         "the message does not name precision:\n" .. out)
      assert_match(out, "corpus/",
         "the message does not name corpus/:\n" .. out)
      assert_match(out, "absent%)",
         "the message does not say corpus/ is absent:\n" .. out)
      assert_no_match(out, "ci%-verify: PASS",
         "ci-verify-complete printed PASS even though it failed:\n" .. out)

      os.execute(("rm -rf %q"):format(dir))
   end)

   it("passes when corpus/ exists, even if empty", function()
      local dir = harness.scratch_dir("ci_verify_with_corpus")
      local copy = dir .. "/Makefile"
      -- Copy the real Makefile, then create an empty corpus/ directory.
      local src = assert(io.open(MAKEFILE, "r"))
      local dst = assert(io.open(copy, "w"))
      dst:write(src:read("*a"))
      src:close()
      dst:close()
      os.execute(("mkdir -p %q"):format(dir .. "/corpus"))

      local out, code = run_ci_verify_complete(dir, copy)

      assert_equal(code, 0,
         "ci-verify-complete failed with corpus/ present:\n" .. out)

      os.execute(("rm -rf %q"):format(dir))
   end)

   it("lists ci-verify-complete as the last prerequisite of ci-verify", function()
      -- Without this wiring the guard never runs and ci-verify still prints PASS
      -- over a skipped measurement. Read the Makefile as text, the only place
      -- the dependency is written down.
      local handle = assert(io.open(MAKEFILE, "r"), "cannot read " .. MAKEFILE)
      local text = handle:read("*a")
      handle:close()

      local deps = assert(ci_verify_line(text),
         "the Makefile has no `ci-verify:` line to check")
      local idx = deps:find("ci%-verify%-complete")
      assert_true(idx ~= nil,
         "ci-verify does not depend on ci-verify-complete: " .. deps)
      -- It must be the LAST prerequisite so the PASS echo only runs if it succeeded.
      local tail = deps:sub(idx)
      assert_true(tail:match("ci%-verify%-complete%s*$"),
         "ci-verify-complete is not the last prerequisite, so PASS could run "
         .. "after a skipped measurement: " .. deps)
   end)
end)
