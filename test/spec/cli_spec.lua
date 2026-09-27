local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match, assert_no_match = harness.assert_equal, harness.assert_true, harness.assert_match, harness.assert_no_match

describe("luasec command line", function()
   it("prints its version and exits 0", function()
      local out, code = harness.cli({ "--version" })
      assert_equal(code, 0, out)
      assert_match(out, "luasec ", out)
   end)

   it("reports a finding for a file with untrusted input reaching a sink, and exits 1", function()
      local out, code = harness.cli({ "test/fixtures/tainted_exec/handler.lua" })
      assert_equal(code, 1, out)
      assert_match(out, "709", out)
      assert_match(out, "handler%.lua:3", out)
      assert_match(out, "os%.execute", out)
   end)

   it("reports nothing for a file with only a constant command, and exits 0", function()
      local out, code = harness.cli({ "test/fixtures/constant_exec/ping.lua" })
      assert_equal(code, 0, out)
      assert_no_match(out, "709", out)
   end)

   it("reports nothing for a file with no sink at all, and exits 0", function()
      local out, code = harness.cli({ "test/fixtures/clean/report.lua" })
      assert_equal(code, 0, out)
   end)

   it("prints help and exits 0", function()
      local out, code = harness.cli({ "--help" })
      assert_equal(code, 0, out)
      assert_match(out, "--format", out)
   end)

   it("exits 2 when asked to analyze a file that does not exist", function()
      local _, code = harness.cli({ "test/fixtures/does_not_exist.lua" })
      assert_equal(code, 2)
   end)

   it("reports a bytecode chunk that names an execution sink, and exits 1", function()
      local out, code = harness.cli({ "test/fixtures/bytecode/sink_exec.luac" })
      assert_equal(code, 1, out)
      assert_match(out, "801", out)
      assert_match(out, "802", out)
      assert_match(out, "os%.execute", out)
      assert_no_match(out, "901", "bytecode must not be reported as a parse error")
   end)

   it("survives a hostile bytecode chunk and exits 1 rather than crashing", function()
      -- hostile_random.luac is 4 KB of noise behind a real signature, so its
      -- version byte is an unknown one. It is reported as bytecode (801) whose
      -- format we cannot claim to match (803); it used to be an 805, which said
      -- the file was not parseable Lua, and it does carry a Lua signature.
      local out, code = harness.cli({ "test/fixtures/bytecode/hostile_random.luac" })
      assert_equal(code, 1, out)
      assert_no_match(out, "stack traceback", "a malformed chunk must not raise")
      assert_no_match(out, "attempt to", out)
      assert_match(out, "801", out)
      assert_match(out, "803", out)
      assert_no_match(out, "802", out)
      assert_no_match(out, "901", out)
   end)

   it("reports a 5.1 chunk as bytecode and a version mismatch, not as a parse error", function()
      local out, code = harness.cli({ "test/fixtures/bytecode/v51.luac" })
      assert_equal(code, 1, out)
      assert_match(out, "801", out)
      assert_match(out, "803", out)
      assert_no_match(out, "901", out)
   end)
end)

describe("luasec --validate", function()
   it("exits 1 and names the sink when the payload reaches os.execute", function()
      local out, code = harness.cli({ "--validate", "test/fixtures/validate/rce.lua" })
      assert_equal(code, 1, out)
      assert_match(out, "rce", out)
      assert_match(out, "os%.execute", out)
   end)

   it("exits 0 when the payload reaches nothing", function()
      local out, code = harness.cli({ "--validate", "test/fixtures/validate/benign.lua" })
      assert_equal(code, 0, out)
      assert_match(out, "benign", out)
   end)

   it("validates a payload piped in on stdin", function()
      local out, code = harness.cli({ "--validate", "--stdin" },
         {stdin = 'os.execute("id")\n'})
      assert_equal(code, 1, out)
      assert_match(out, "rce", out)
      assert_match(out, "os%.execute", out)
   end)

   it("exits 2 without a stack trace when the payload does not parse", function()
      local out, code = harness.cli({ "--validate", "test/fixtures/validate/malformed.lua" })
      assert_equal(code, 2, out)
      assert_match(out, "error", out)
      assert_no_match(out, "stack traceback")
      assert_no_match(out, "%.lua:%d+:")
   end)

   it("exits 2 when --validate is given nothing to validate", function()
      local _, code = harness.cli({ "--validate" })
      assert_equal(code, 2)
   end)

   it("keeps a payload's own writes out of the command line's stdout", function()
      local out, code = harness.cli({ "--validate", "test/fixtures/validate/noisy.lua" })
      assert_equal(code, 0, out)
      assert_match(out, "verdict:%s+benign", out)
      -- The payload's bytes are reported inside the verdict, on their own lines,
      -- not spliced into the report where a log reader would take them for ours.
      assert_match(out, "| PAYLOAD%-PRINTED%-THIS", out)
      assert_no_match(out, "^PAYLOAD%-PRINTED%-THIS", out)
   end)
end)
