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

describe("bytecode triage: text files are unaffected", function()
   it("analyzes a source file with a sink exactly as it did before", function()
      local report = api.check_source("local function s(h)\n  return os.execute(h)\nend\n")
      assert_true(codes(report):find("708", 1, true) ~= nil,
         "expected the ordinary source finding 708, got " .. codes(report))
      assert_true(codes(report):find("80", 1, true) == nil,
         "a source file must not produce a bytecode finding")
   end)

   it("reports nothing extra for a clean source file", function()
      local report = api.check_source("local function add(a, b) return a + b end\nreturn add(1, 2)\n")
      assert_equal(codes(report), "")
   end)

   it("still reports 901 for source that does not parse", function()
      -- 805 is for a file that claims to be bytecode and cannot be read; plain
      -- text that does not parse is still a 901.
      local report = api.check_source("local function broken(\n")
      assert_equal(codes(report), "901")
   end)

   it("analyzes a mixed input list, bytecode and text together", function()
      local report = api.analyze({
         "test/fixtures/bytecode/sink_exec.luac",
         "test/fixtures/tainted_exec/handler.lua",
      })
      assert_true(codes(report):find("802", 1, true) ~= nil, codes(report))
      assert_true(codes(report):find("709", 1, true) ~= nil, codes(report))
      assert_true(codes(report):find("901", 1, true) == nil, codes(report))
   end)

   it("still reports 901 for a path it cannot read", function()
      local report = api.analyze({"test/fixtures/does_not_exist.lua"})
      assert_equal(codes(report), "901")
   end)
end)

describe("bytecode triage: the assumed interpreter", function()
   local function analyze(name, opts)
      return api.analyze({"test/fixtures/bytecode/" .. name .. ".luac"}, opts)
   end

   it("treats a 5.4 chunk as matching by default", function()
      assert_true(codes(analyze("hello")):find("803", 1, true) == nil)
   end)

   it("reports 803 for a 5.4 chunk when 5.1 is assumed", function()
      local report = analyze("hello", {assume_version = "5.1"})
      assert_equal(codes(report), "801,803")
   end)

   it("does not report 803 for a 5.1 chunk when 5.1 is assumed", function()
      local report = analyze("v51", {assume_version = "5.1"})
      assert_true(codes(report):find("803", 1, true) == nil, codes(report))
      assert_true(codes(report):find("801", 1, true) ~= nil, codes(report))
   end)

   it("still reads the constant table of a chunk whose version does not match", function()
      -- 803 says the format may not be one we reason about. It must not stop us
      -- reading what we can: a 5.1 chunk that names a sink is still a 802.
      local report = analyze("v51")
      assert_equal(codes(report), "801,802,803")
   end)
end)
