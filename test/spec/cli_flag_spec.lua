-- The command line's own behaviour: which flag values are configuration, which
-- are findings, and what a run says when it covered less ground than it was
-- asked to.
--
-- Every case here is a defect that was live in this codebase. The exit code is
-- the whole subject: this tool defines 1 as "findings", so a configuration
-- mistake that exits 1 is a security result handed to a CI, and a coverage gap
-- that exits 0 is a clean bill of health for a file nobody read.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match, assert_no_match =
   harness.assert_equal, harness.assert_true, harness.assert_match, harness.assert_no_match
local scratch_dir = harness.scratch_dir

local function write_file(path, text)
   local handle = assert(io.open(path, "w"))
   handle:write(text)
   handle:close()
   return path
end

local function rm(dir)
   os.execute("rm -rf " .. string.format("%q", dir))
end

-- Non-empty lines of a run's output. A configuration error is one line: a
-- paragraph explaining it is a traceback wearing a different hat.
local function output_lines(out)
   local count = 0
   for line in out:gmatch("[^\n]+") do
      if line:match("%S") then count = count + 1 end
   end
   return count
end

-- The same run with stderr discarded, to tell a message on stderr from one on
-- stdout. harness.cli joins the two streams, which is right for most assertions
-- and wrong for this one.
local function stdout_only(args)
   local cmd = "./bin/luasec"
   for _, a in ipairs(args) do cmd = cmd .. " " .. string.format("%q", a) end
   local pipe = assert(io.popen(cmd .. " 2>/dev/null"))
   local out = pipe:read("*a")
   pipe:close()
   return out
end

-- Is this path readable by the user running the spec? macOS and Linux both refuse
-- a 000 file to its owner; where the test runs as a user that bypasses
-- permissions there is nothing to assert, so the caller skips rather than
-- asserting against noise.
local function unreadable(path)
   local handle = io.open(path, "rb")
   if handle then handle:close() return false end
   return true
end

-- A file whose only finding is a 709: untrusted input reaching a sink, which is
-- what an operator is selecting for when they reach for --only.
local RCE = table.concat({
   "local function ping(host)",
   '   os.execute("ping -c1 " .. http.formvalue(host))',
   "end",
   "return ping",
}, "\n")

describe("--only", function()
   it("matches the operator's pattern against the code, not the other way round", function()
      -- `string.match(finding.code, code_pattern)` was written as
      -- `code_pattern:match(finding.code)`, and the argument order reads
      -- plausibly enough to survive review. The result was that every
      -- multi-character pattern matched nothing: --only 70, --only 7 and the
      -- documented --only 70[0-9] all reported an empty tree and exited 0, which
      -- is a clean bill of health for a file with a critical RCE in it.
      local dir = scratch_dir("cliflag_only_direction")
      write_file(dir .. "/h.lua", RCE .. "\n")

      for _, pattern in ipairs({"709", "70", "7", "70[0-9]"}) do
         local out, code = harness.cli({"--std", "+luci", "--only", pattern, dir})
         assert_equal(code, 1, "--only " .. pattern .. " selected nothing:\n" .. out)
         assert_match(out, "709", "--only " .. pattern .. ":\n" .. out)
         assert_match(out, "h%.lua", "--only " .. pattern .. ":\n" .. out)
      end

      rm(dir)
   end)

   it("rejects a pattern Lua cannot read, as a config error", function()
      -- `--only '[bad'` matched nothing, so every finding read as "not selected"
      -- and a file with a critical RCE came back clean with exit 0. A pattern
      -- nobody can read is a typo in the invocation, so it is exit 2 and the
      -- pattern is named: the in-source directive path had already learned this
      -- and the command line had not.
      local dir = scratch_dir("cliflag_only_bad")
      write_file(dir .. "/h.lua", RCE .. "\n")
      local out, code = harness.cli({"--only", "[bad", dir})
      rm(dir)

      assert_equal(code, 2, out)
      assert_match(out, "%[bad", "the message names the pattern: " .. out)
      assert_no_match(out, "stack traceback", out)
      assert_no_match(out, "0 findings", "a config error is not a clean report: " .. out)
   end)

   it("says out loud when it selects nothing, and still exits 0", function()
      -- An empty selection cannot be an error: `--only 709` on a file with no 709
      -- is a legitimate thing to ask for, so making it one would make --only
      -- unusable. The trade-off is the test: silence from luasec means "looked
      -- at it and found nothing", and this has to distinguish that from "the
      -- pattern you meant matched nothing".
      local out, code = harness.cli({"--only", "709", "test/fixtures/clean/report.lua"})
      assert_equal(code, 0, "an empty selection is not an error: " .. out)
      assert_match(out, "%-%-only selected nothing", out)
      assert_match(out, "709", "the warning names the pattern: " .. out)
      assert_match(out, "0 findings", out)

      -- On stderr. A machine reading the report off stdout must not see a
      -- sentence about the invocation in the middle of its data.
      local only_stdout = stdout_only({"--only", "709", "test/fixtures/clean/report.lua"})
      assert_no_match(only_stdout, "selected nothing",
         "the warning is on stderr, not in the report: " .. only_stdout)
      assert_match(only_stdout, "0 findings", only_stdout)
   end)
end)

describe("a numeric option that is not a positive integer", function()
   it("is a config error, never a security result", function()
      -- `--max-nodes $UNSET_VAR` reached the analysis as the string "abc" and
      -- `max_nodes + 1` raised out of the CLI with exit 1, which this tool
      -- defines as "findings": a CI with a typo in a variable gets a security
      -- result. 1.5 is the same class of mistake, found by reading the message
      -- rather than the code: the message said positive integer and the check
      -- said positive number, so a fractional node cap degraded the analysis and
      -- the run exited 1 on the degradation it had caused.
      for _, option in ipairs({"--max-nodes", "--jobs"}) do
         for _, value in ipairs({"abc", "0", "-5", "1.5", ""}) do
            local out, code = harness.cli({option, value, "test/fixtures/clean/report.lua"})
            assert_equal(code, 2, option .. " " .. value .. " is not a finding: " .. out)
            assert_equal(output_lines(out), 1,
               option .. " " .. value .. " answers on one line: " .. out)
            assert_match(out, "positive integer", out)
            assert_no_match(out, "stack traceback", out)
         end
      end
   end)
end)

describe("--format", function()
   it("refuses a format it does not have, and writes nothing", function()
      -- An unknown format used to fall back to plain text, so
      -- `--format json -o report.json` wrote prose into a file a CI then handed to
      -- a JSON parser, and the failure surfaced downstream as a parse error in a
      -- tool that was never wrong. A typo in a flag is a config error, like the
      -- numbers -- and the file the operator named must not exist at all, or the
      -- next step of their pipeline reads an empty file and calls it a pass.
      local dir = scratch_dir("cliflag_format")
      write_file(dir .. "/h.lua", RCE .. "\n")
      local target = dir .. "/report.json"

      local out, code = harness.cli({"--format", "bogus", "-o", target, dir})
      local written = io.open(target, "rb")
      if written then written:close() end
      rm(dir)

      assert_equal(code, 2, out)
      assert_match(out, "bogus", "the message names the format: " .. out)
      assert_equal(output_lines(out), 1, "a config error answers on one line: " .. out)
      assert_no_match(out, "stack traceback", out)
      assert_true(written == nil, "no report was written under a name that was not a format")
   end)
end)

describe("a file that could not be read", function()
   it("fails the run under a threshold, a code filter and --only alike", function()
      -- Three ways an operator quiets a report, and none of them may turn a file
      -- nobody read into a green build: --fail-on is a severity floor, the
      -- threshold is a report filter, and --only narrows what the operator wants
      -- to read. None of them is a way to green a run that covered less ground
      -- than it was asked to.
      local dir = scratch_dir("cliflag_unreadable")
      local file = write_file(dir .. "/locked.lua", "local x = 1\n")
      os.execute("chmod 000 " .. string.format("%q", file))
      local really_unreadable = unreadable(file)

      local runs = {
         {"--fail-on=high"},
         {"--severity-threshold", "critical"},
         {"--only", "701"},
      }
      local seen = {}
      if really_unreadable then
         for _, args in ipairs(runs) do
            args[#args + 1] = dir
            local out, code = harness.cli(args)
            seen[#seen + 1] = {label = args[1], out = out, code = code}
         end
      end

      os.execute("chmod 644 " .. string.format("%q", file))
      rm(dir)

      for _, run in ipairs(seen) do
         assert_true(run.code ~= 0,
            run.label .. " hid a file that was never analyzed:\n" .. run.out)
         assert_match(run.out, "901",
            run.label .. " dropped the evidence that it was never analyzed:\n" .. run.out)
      end
   end)
end)

describe("a file with no source to read", function()
   it("is reported and fails the run, whatever the threshold", function()
      -- There is one list of codes meaning "we did not read this file" and it
      -- used to be written out three times: in the exit code, in the severity
      -- threshold, and in the baseline. The copies had already drifted once: the
      -- bytecode codes were added to one and not the other - so
      -- `--severity-threshold critical` over a .luac printed nothing and exited 1,
      -- an empty report and a red build, which reads as a contradiction rather
      -- than as a failure to read the file. The threshold quiets low-severity
      -- findings; the bytecode findings ARE low-severity, and a file that cannot
      -- be read is not a low-severity finding.
      local dir = scratch_dir("cliflag_degraded")
      local broken = write_file(dir .. "/broken.lua", 'local x = "unterminated\n')

      local cases = {
         {path = "test/fixtures/bytecode/hello.luac", code = "801"},
         {path = "test/fixtures/bytecode/v51.luac", code = "803"},
         {path = "test/fixtures/bytecode/truncated.luac", code = "805"},
         {path = broken, code = "901"},
      }

      for _, case in ipairs(cases) do
         local out, code = harness.cli({"--severity-threshold", "critical", case.path})
         assert_true(code ~= 0,
            case.path .. " is not an analyzed file, so the run cannot be green:\n" .. out)
         assert_match(out, case.code,
            "the " .. case.code .. " is printed, not merely counted:\n" .. out)
      end

      rm(dir)
   end)
end)

describe("a suppression region and ground we did not cover", function()
   it("still reports a directory it could not read under --only", function()
      -- --only narrows what the operator wants to read; it does not remove the
      -- evidence that a directory was never analyzed. A run that skipped ground
      -- must not print a clean report and exit non-zero, which reads as a
      -- contradiction: "nothing to report" and "here is what I found" cannot both
      -- be true of the same run.
      local dir = scratch_dir("cliflag_only_and_locked")
      os.execute("mkdir " .. string.format("%q", dir .. "/locked"))
      -- A push/pop region in the file we can read. Its findings are of a code
      -- --only drops, so the only thing left in the report is the coverage gap.
      write_file(dir .. "/pushpop.lua", table.concat({
         "-- luasec: push",
         "-- luasec: ignore 701",
         "os.execute(cmd)",
         "-- luasec: pop",
         "os.execute(cmd)",
         "",
      }, "\n"))
      os.execute("chmod 000 " .. string.format("%q", dir .. "/locked"))
      local really_unreadable = unreadable(dir .. "/locked")

      local out, code
      if really_unreadable then out, code = harness.cli({"--only", "708", dir}) end

      os.execute("chmod 755 " .. string.format("%q", dir .. "/locked"))
      rm(dir)

      if really_unreadable then
         assert_match(out, "901", "the unreadable directory is still reported:\n" .. out)
         assert_match(out, "not analyzed", out)
         assert_no_match(out, "0 findings",
            "a run that skipped ground must not print a clean report:\n" .. out)
         assert_true(code ~= 0, "a run that skipped ground must not exit clean:\n" .. out)
      end
   end)
end)
