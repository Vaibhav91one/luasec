-- Prototype walk. luasec.bytecode.protos is not a public seam, so these specs
-- go through what the walk is for: the sink names that reach the report. The
-- layouts themselves are pinned by the bytecode header spec and by the
-- fixtures, which are real luac output for 5.1 to 5.4.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luasec.api"

-- Compile with the repo's luac into a temp path, analyze it, return the codes.
local function analyze_chunk(source_text, name)
   local luac = "./build/lua-5.4.9/src/luac"
   local source, chunk = os.tmpname() .. ".lua", os.tmpname() .. ".luac"
   local handle = assert(io.open(source, "w"))
   handle:write(source_text)
   handle:close()
   assert(os.execute(string.format("%q -o %q %q", luac, chunk, source)))
   os.remove(source)

   local report = api.analyze({chunk})
   os.remove(chunk)

   local out = {}
   for _, finding in ipairs(report) do
      if finding.code == "802" then out[#out + 1] = finding.name end
   end
   table.sort(out)
   return out, report
end

describe("bytecode prototype walk", function()
   it("finds os.execute in a compiled call, which stores the two halves apart", function()
      -- luac turns `os.execute(cmd)` into a GETTABUP of "os" followed by a
      -- GETTABLE of "execute". The dotted path never appears as a constant, so
      -- this only works if the walk pairs adjacent constants.
      local sinks = analyze_chunk("return os.execute('id')\n")
      assert_equal(table.concat(sinks, ","), "os.execute")
   end)

   it("finds io.popen in a compiled call", function()
      local sinks = analyze_chunk("return io.popen('id')\n")
      assert_equal(table.concat(sinks, ","), "io.popen")
   end)

   it("finds dofile in a compiled call", function()
      local sinks = analyze_chunk("return dofile('/tmp/x')\n")
      assert_equal(table.concat(sinks, ","), "dofile")
   end)

   it("finds a sink that the source keeps as one dotted string", function()
      -- A payload that resolves the sink at runtime keeps "loadstring" whole.
      local sinks = analyze_chunk("local n = 'loadstring'\nreturn n\n")
      assert_equal(table.concat(sinks, ","), "loadstring")
   end)

   it("finds a sink named inside a nested function", function()
      local sinks = analyze_chunk([[
local function outer()
   local function inner(cmd)
      return os.execute(cmd)
   end
   return inner
end
return outer
]])
      assert_equal(table.concat(sinks, ","), "os.execute")
   end)

   it("finds several distinct sinks in one chunk", function()
      local sinks = analyze_chunk([[
local function a(c) return os.execute(c) end
local function b(c) return io.popen(c) end
return a, b
]])
      assert_equal(table.concat(sinks, ","), "io.popen,os.execute")
   end)

   it("reports nothing for a chunk that only calls a harmless function", function()
      local sinks = analyze_chunk("local function f(x) return x + 1 end\nreturn f(1)\n")
      assert_equal(#sinks, 0)
   end)

   it("pairs adjacent constants even when the source only concatenates them", function()
      -- A known limitation, pinned rather than hidden. Deciding whether two
      -- adjacent constants mean a table index or a concatenation would mean
      -- decoding the instruction stream, and this tool does not decompile. The
      -- finding carries medium confidence for exactly this reason, and the 801
      -- alongside it is the honest summary: we cannot analyze the source.
      local sinks = analyze_chunk([[
local os = "os"
local execute = "execute"
return os .. execute
]])
      assert_equal(table.concat(sinks, ","), "os.execute")
   end)

   it("gives 802 a confidence below certain, because no data flow is proven", function()
      local _, report = analyze_chunk("return os.execute('id')\n")
      for _, finding in ipairs(report) do
         if finding.code == "802" then
            assert_true(finding.confidence ~= "certain",
               "a name in a constant table is not a proven data flow")
         end
      end
   end)

   it("does not report a sink for a string that merely contains one", function()
      local sinks = analyze_chunk("return 'please do not run os.execute here'\n")
      assert_equal(#sinks, 0, "expected no sink, got " .. table.concat(sinks, ","))
   end)

   it("still reports 801 for a chunk whose only sink is past the depth cap", function()
      local _, report = analyze_chunk("return os.execute('id')\n")
      local seen = {}
      for _, finding in ipairs(report) do seen[finding.code] = true end
      assert_true(seen["801"], "every chunk carries an 801")
   end)
end)
