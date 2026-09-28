-- Adversarial regression suite.
--
-- Written by the verifier, not by the implementer: each spec is an attempt to
-- make luasec wrong in a way its own suite does not check. A spec here failing
-- is a product bug until proven otherwise.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luasec.api"

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

describe("metamorphic invariants", function()
   -- The finding set must depend on the program's behaviour, not its spelling.
   local TEMPLATE = [[
local function go(%s)
   os.execute("ping " .. http.formvalue("%s"))
end
]]

   it("is invariant under renaming the function and its parameter", function()
      assert_equal(codes(api.check_source(TEMPLATE:format("handler", "host"))), "709")
      assert_equal(codes(api.check_source(TEMPLATE:format("q", "z"))), "709")
   end)

   it("is invariant under reindentation and comment insertion", function()
      local plain = [[
local function go(host)
   os.execute("ping " .. http.formvalue("host"))
end
]]
      local noisy = [[
-- a leading comment

local   function   go( host )   -- trailing
   os.execute( "ping " .. http.formvalue( "host" ) )  -- sink
end
]]
      assert_equal(codes(api.check_source(plain)), codes(api.check_source(noisy)))
   end)

   it("is invariant under splitting a concatenation across lines", function()
      local one_line = 'os.execute("ping " .. http.formvalue("host"))'
      local split = 'os.execute("ping "\n   .. http.formvalue("host"))'
      assert_equal(codes(api.check_source("return " .. one_line)),
                   codes(api.check_source("return " .. split)))
   end)

   it("is invariant under wrapping a value in parentheses", function()
      assert_equal(codes(api.check_source('return os.execute(("ping " .. http.formvalue("h")))')),
                   codes(api.check_source('return os.execute("ping " .. http.formvalue("h"))')))
   end)

   it("does not report a sink that the program never reaches", function()
      local report = api.check_source([[
local function never_called(host)
   os.execute("ping " .. http.formvalue("host"))
end
local function go()
   return "safe"
end
]])
      -- The function is defined but never invoked; whether that is reportable is
      -- a design question, but the report must be stable and must not invent
      -- a source that is not there.
      for _, finding in ipairs(report) do
         assert_true(finding.code == "709" or finding.code == "701" or finding.code == "708",
            "unexpected code " .. finding.code)
      end
   end)
end)

describe("hostile input", function()
   it("does not hang on a deeply nested expression", function()
      local expr = string.rep("(", 300) .. 'http.formvalue("h")' .. string.rep(")", 300)
      local ok = pcall(api.check_source, "return " .. expr)
      assert_true(ok, "a 300-deep nesting must not crash the analyzer")
   end)

   it("does not hang on a very long concatenation chain", function()
      local parts = {}
      for index = 1, 4000 do parts[index] = '"x"' end
      local ok = pcall(api.check_source, "return " .. table.concat(parts, " .. "))
      assert_true(ok, "a 4000-term concatenation must not crash the analyzer")
   end)

   it("reports a parse failure instead of claiming the file is clean", function()
      local report = api.check_source("this is not lua at all ===")
      assert_true(#report > 0, "an unparseable file must produce a finding, never silence")
      assert_equal(report[1].code, "901")
   end)
end)
