local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_nil = harness.assert_equal, harness.assert_true, harness.assert_nil

local api = require "luasec.api"

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

local function analyze(name)
   return api.analyze({"test/fixtures/bytecode/" .. name .. ".luac"})
end

describe("bytecode triage: a precompiled Lua chunk", function()
   it("is reported as 801 rather than as a parse error", function()
      local report = analyze("hello")
      assert_true(codes(report):find("801", 1, true) ~= nil,
         "expected an 801 finding, got " .. codes(report))
      assert_nil(codes(report):find("901", 1, true),
         "a bytecode chunk must never be reported as a parse error")
   end)

   it("reports a Lua 5.1 chunk as 801 with 803, not as a parse error", function()
      local report = analyze("v51")
      assert_equal(codes(report), "801,802,803",
         "a 5.1 chunk is bytecode, and its version is not the assumed 5.4")
      local report_801
      for _, finding in ipairs(report) do
         if finding.code == "801" then report_801 = finding end
      end
      assert_equal(report_801.name, "Lua 5.1")
   end)

   it("reports a LuaJIT chunk as bytecode of its own flavor", function()
      local report = analyze("luajit")
      assert_equal(codes(report), "801,803")
      for _, finding in ipairs(report) do
         if finding.code == "801" then assert_equal(finding.flavor, "luajit") end
      end
   end)

   it("reports constants naming an execution sink as 802", function()
      local report = analyze("sink_exec")
      assert_equal(codes(report), "801,802")
      for _, finding in ipairs(report) do
         if finding.code == "802" then
            assert_equal(finding.name, "os.execute")
            assert_equal(finding.severity, "high")
         end
      end
   end)

   it("does not report 802 for a chunk whose constants name no sink", function()
      local report = analyze("hello")
      assert_equal(codes(report), "801")
   end)

   it("stops walking prototypes at the depth cap without reporting the buried sink", function()
      -- The innermost prototype of hostile_depth.luac names os.execute, past the
      -- cap of 64. Reporting 802 would mean the cap is not real.
      local report = analyze("hostile_depth")
      assert_equal(codes(report), "801,805")
   end)

   it("stops reading a constant table past the cap without reporting the buried sink", function()
      local report = analyze("hostile_constants")
      assert_equal(codes(report), "801,805")
   end)
end)

describe("bytecode triage: a version byte we have no reader for", function()
   it("is reported as a format that does not match the assumed interpreter", function()
      -- The signature is real, so the file is bytecode and its source cannot be
      -- analyzed (801). Its version byte names no release, so it is not the
      -- interpreter we assume is running (803). It is emphatically not 805: we
      -- are not saying the file failed to parse, we are saying we cannot claim
      -- to know what it is.
      local report = analyze("unknown_version")
      assert_equal(codes(report), "801,803",
         "an unrecognized version byte is a 801 and a 803")

      local report_801, report_803
      for _, finding in ipairs(report) do
         if finding.code == "801" then report_801 = finding end
         if finding.code == "803" then report_803 = finding end
      end
      assert_equal(report_801.name, "Lua (unknown version 0x99)",
         "the 801 should say which version byte was read")
      assert_true(report_803.assumed_version == nil or report_803.assumed_version == "5.4",
         "the 803 names the interpreter we assume, got " .. tostring(report_803.assumed_version))
   end)

   it("does not report a sink read from a layout the version byte never claimed", function()
      -- unknown_version.luac is sink_exec.luac with one byte changed, so the
      -- string "os.execute" really is in the constant table. Reading it means
      -- walking the file as 5.4 on no evidence but our own assumption, and
      -- reporting a high severity finding off a layout we cannot justify.
      local report = analyze("unknown_version")
      assert_nil(codes(report):find("802", 1, true),
         "constants must not be read from an unverified layout: " .. codes(report))

      local report_802 = analyze("sink_exec")
      assert_true(codes(report_802):find("802", 1, true) ~= nil,
         "the same chunk with a version byte we do know is still a 802")
   end)
end)

describe("bytecode triage: malformed and hostile input", function()
   local HOSTILE = {
      {"tiny", "eight bytes: a signature and nothing else"},
      {"truncated", "cut in the middle of the numeric markers"},
      {"wrong_endian", "the LUAC_INT marker byte reversed"},
      {"hostile_random", "4 KB of noise behind a valid signature"},
      {"hostile_sizes", "a constant claiming a gigabyte-long string"},
      {"hostile_constants", "a constant table claiming 200001 entries"},
      {"hostile_depth", "100 nested prototypes, past the depth cap"},
   }

   for _, fixture in ipairs(HOSTILE) do
      it("reports " .. fixture[1] .. " without crashing (" .. fixture[2] .. ")", function()
         local report = analyze(fixture[1])
         assert_true(#report > 0, "expected at least one finding")
         assert_nil(codes(report):find("901", 1, true),
            "malformed bytecode must not be reported as a source parse error")
         for _, finding in ipairs(report) do
            assert_true(finding.message ~= nil, "every finding needs a message")
         end
      end)
   end

   -- 803 joined the list because a chunk can carry a real PUC signature and a
   -- version byte that names no release. hostile_random.luac is one: its byte 5
   -- is random, so it is an unknown version by accident rather than by design.
   -- 805 would say such a file is "not parseable Lua despite its name", which
   -- is false -- the signature is there. 803 says what we can actually claim,
   -- which is that we do not know what it is.
   --
   -- 802 stays off the list on purpose. It is the code that carries a severity
   -- and a CWE, so producing one out of a layout the version byte never claimed
   -- is exactly the failure this whole set exists to prevent.
   it("gives every hostile chunk a 801, 803 or 805 and never a 802", function()
      for _, fixture in ipairs(HOSTILE) do
         local report = analyze(fixture[1])
         for _, finding in ipairs(report) do
            assert_true(
               finding.code == "801" or finding.code == "803" or finding.code == "805",
               fixture[1] .. " produced an unexpected " .. finding.code)
         end
         assert_nil(codes(report):find("802", 1, true),
            fixture[1] .. " reported a sink read from a layout it never established")
      end
   end)
end)
