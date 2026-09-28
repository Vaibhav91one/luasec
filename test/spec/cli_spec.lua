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
      -- The parse position is reported against the file the operator passed, not
      -- against a name only the sandbox knows.
      assert_match(out, "could not be compiled", out)
      assert_match(out, "malformed%.lua:2", out)
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
      -- labelled as the payload's, not spliced into the report where a log
      -- reader would take them for ours.
      assert_match(out, "payload| PAYLOAD%-PRINTED%-THIS", out)
      assert_match(out, "payload| PAYLOAD%-WROTE%-THIS", out)
      assert_no_match(out, "^PAYLOAD%-PRINTED%-THIS", out)
      assert_no_match(out, "^payload| ", out, "a payload line reached the top of the report")
   end)

   it("labels a payload's forged records as payload text rather than as findings", function()
      local out, code = harness.cli({ "--validate", "--stdin" }, {stdin = [[
io.stdout:write("__LUASEC_CHAIN__ 9:INJECTED\n")
io.stdout:write("__LUASEC_OUTPUT__ 20:FORGED OPERATOR TEXT\n")
return 1
]]})
      assert_equal(code, 0, out)

      -- The forged chain entry must not appear as a step in the chain ...
      assert_no_match(out, "chain:%s+INJECTED", out)
      -- ... and both forged records come back as the payload's own text, in the
      -- gutter, under a heading that says what they are.
      assert_match(out, "payload output", out)
      assert_match(out, "payload| __LUASEC_CHAIN__ 9:INJECTED", out)
      assert_match(out, "payload| __LUASEC_OUTPUT__ 20:FORGED OPERATOR TEXT", out)
   end)

   it("names the file it validated and the interpreter that produced the verdict", function()
      local out = harness.cli({ "--validate", "test/fixtures/validate/rce.lua" })

      assert_match(out, "validation of test/fixtures/validate/rce%.lua", out)
      assert_match(out, "rce%.lua:3", out, "the sink was not traced back to the file")
      assert_match(out, "lua:%s+", out)
   end)
end)

-- A unique directory under /tmp, created eagerly so the path is a directory
-- rather than a name inside one.
local scratch_serial = 0
local function scratch_dir(tag)
   scratch_serial = scratch_serial + 1
   local dir = os.getenv("TMPDIR") or "/tmp"
   dir = dir:gsub("/$", "")
   dir = ("%s/luasec_spec_%s_%d_%d"):format(dir, tag, os.time(), scratch_serial)
   assert_true(os.remove(dir) == nil or true, "scratch path is free")
   os.execute("mkdir -p " .. string.format("%q", dir))
   return dir
end

describe("a directory the walk cannot read", function()
   it("fails the run instead of reporting a clean tree", function()
      -- macOS and Linux both refuse a 000 directory to the owner. Where the
      -- test runs as a user that bypasses permissions, there is nothing to
      -- assert, so the case is skipped rather than asserted against noise.
      local dir = scratch_dir("walk")
      local locked = dir .. "/locked"
      os.execute("mkdir " .. string.format("%q", locked))
      -- Untrusted input reaching a sink, so this file has a finding of its
      -- own: the point of the test is that we report what we could read AND
      -- what we could not.
      local f = assert(io.open(dir .. "/visible.lua", "w"))
      f:write('local function ping(host)\n   os.execute("ping -c1 " .. http.formvalue(host))\nend\nreturn ping\n')
      f:close()
      os.execute("chmod 000 " .. string.format("%q", locked))

      local probe = io.popen("ls " .. string.format("%q", locked) .. " 2>/dev/null")
      local readable = probe:read("*a")
      probe:close()
      local out, code = harness.cli({ dir })

      os.execute("chmod 755 " .. string.format("%q", locked))
      os.execute("rm -rf " .. string.format("%q", dir))

      if readable == "" then
         -- The unreadable directory really was unreadable.
         assert_true(code ~= 0,
            "a tree we could not fully read must not exit clean:\n" .. out)
         assert_match(out, "901", out)
         assert_match(out, "not analyzed", out)
         -- The file we could read is still reported, and nothing is invented.
         assert_match(out, "visible%.lua", out)
      end
   end)

   it("reports nothing for a tree it can read completely", function()
      local dir = scratch_dir("walk_clean")
      local f = assert(io.open(dir .. "/ok.lua", "w"))
      f:write("local x = 1\n")
      f:close()
      local out, code = harness.cli({ dir })
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 0, out)
      assert_no_match(out, "901", out)
   end)
end)

describe("--fail-on", function()
   it("does not report success for a run that could not read everything", function()
      local dir = scratch_dir("fail_on")
      os.execute("mkdir " .. string.format("%q", dir .. "/locked"))
      local f = assert(io.open(dir .. "/quiet.lua", "w"))
      f:write("local x = 1\n")
      f:close()
      os.execute("chmod 000 " .. string.format("%q", dir .. "/locked"))

      local probe = io.popen("ls " .. string.format("%q", dir .. "/locked") .. " 2>/dev/null")
      local unreadable = probe:read("*a") == ""
      probe:close()
      local out, code = harness.cli({ "--fail-on=high", dir })

      os.execute("chmod 755 " .. string.format("%q", dir .. "/locked"))
      os.execute("rm -rf " .. string.format("%q", dir))

      if unreadable then
         -- The threshold exists to quieten low-severity findings. It is not a
         -- way to green a run that covered less ground than it was asked to.
         assert_true(code ~= 0, "--fail-on=high hid a tree we could not read:\n" .. out)
         assert_match(out, "not analyzed", out)
      end
   end)
end)

describe("asking for one code does not hide ground we did not cover", function()
   it("still reports an unreadable directory under --only", function()
      local dir = scratch_dir("only_locked")
      os.execute("mkdir " .. string.format("%q", dir .. "/locked"))
      local f = assert(io.open(dir .. "/a.lua", "w"))
      f:write('os.execute("x")\n')
      f:close()
      os.execute("chmod 000 " .. string.format("%q", dir .. "/locked"))

      local probe = io.popen("ls " .. string.format("%q", dir .. "/locked") .. " 2>/dev/null")
      local unreadable = probe:read("*a") == ""
      probe:close()
      local out, code = harness.cli({ "--only", "708", dir })

      os.execute("chmod 755 " .. string.format("%q", dir .. "/locked"))
      os.execute("rm -rf " .. string.format("%q", dir))

      if unreadable then
         -- Exit 1 with an empty report would read as a contradiction. --only
         -- narrows what the operator wants to read; it does not remove the
         -- evidence that a directory was never analyzed.
         assert_match(out, "901", out)
         assert_match(out, "not analyzed", out)
         assert_true(code ~= 0, "a run that skipped ground must not exit clean:\n" .. out)
      end
   end)

   it("names every unreadable directory, not only the first", function()
      local dir = scratch_dir("many_locked")
      for _, name in ipairs({"l1", "l2", "l3"}) do
         os.execute("mkdir " .. string.format("%q", dir .. "/" .. name))
         os.execute("chmod 000 " .. string.format("%q", dir .. "/" .. name))
      end

      local probe = io.popen("ls " .. string.format("%q", dir .. "/l1") .. " 2>/dev/null")
      local unreadable = probe:read("*a") == ""
      probe:close()
      local out, code = harness.cli({ dir })

      for _, name in ipairs({"l1", "l2", "l3"}) do
         os.execute("chmod 755 " .. string.format("%q", dir .. "/" .. name))
      end
      os.execute("rm -rf " .. string.format("%q", dir))

      if unreadable then
         local count = select(2, out:gsub("could not read directory", ""))
         assert_equal(count, 3,
            "one fix-and-rerun per directory is three cycles; name all of them:\n" .. out)
         assert_true(code ~= 0, out)
      end
   end)

   it("fails a run whose file could not be parsed, whatever the threshold", function()
      local dir = scratch_dir("badparse")
      local f = assert(io.open(dir .. "/broken.lua", "w"))
      f:write('local x = "unterminated\n')
      f:close()
      local out, code = harness.cli({ "--fail-on=high", dir })
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_true(code ~= 0,
         "--fail-on quiets low-severity findings; it does not excuse a file "
         .. "that was never analyzed:\n" .. out)
   end)
end)
