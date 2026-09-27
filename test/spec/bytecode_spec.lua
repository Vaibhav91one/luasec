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

   it("gives every hostile chunk a 801 or a 805 and nothing else", function()
      for _, fixture in ipairs(HOSTILE) do
         local report = analyze(fixture[1])
         for _, finding in ipairs(report) do
            assert_true(finding.code == "801" or finding.code == "805",
               fixture[1] .. " produced an unexpected " .. finding.code)
         end
      end
   end)
end)
