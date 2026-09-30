local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luasec.api"
local escapes = require "luasec.engine.escapes"

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

local function has_code(report, code)
   for _, finding in ipairs(report) do
      if finding.code == code then return true end
   end
   return false
end

describe("unknown string escapes (Lua 5.1 compat)", function()
   it("reports 709 and no 901 for <\\/a> before a tainted os.execute", function()
      local src = 'local s = "<\\/a>"\nos.execute("x " .. http.formvalue("h"))\n'
      local report = api.check_source(src, {std = "luci"})
      assert_true(has_code(report, "709"), "expected a 709, got " .. codes(report))
      assert_true(not has_code(report, "901"), "expected no 901, got " .. codes(report))
   end)

   it("parses \\. and \\- inside single-quoted strings without a 901", function()
      local src = "local a = '\\.'\nlocal b = '\\-'\nprint(a, b)\n"
      local report = api.check_source(src, {std = "luci"})
      assert_true(not has_code(report, "901"), "expected no 901, got " .. codes(report))
   end)

   it("leaves valid escapes byte-for-byte unchanged", function()
      local src = 'local s = "a\\nb\\tc\\\\d\\"e\\065\\x41\\z   \\u{48}"\n'
      assert_equal(escapes.normalise(src), src, "valid escapes must not be touched")
   end)

   it("leaves unknown escapes in comments and long strings alone", function()
      local comment = "-- a \\/ comment\nprint(1)\n"
      assert_equal(escapes.normalise(comment), comment, "line comment untouched")
      local block = "--[[ a \\/ block ]]\nprint(1)\n"
      assert_equal(escapes.normalise(block), block, "block comment untouched")
      local long = "local s = [[a \\/ b]]\nprint(s)\n"
      assert_equal(escapes.normalise(long), long, "long string untouched")
   end)

   it("still reports 901 for a real syntax error", function()
      local report = api.check_source("local = \n", {std = "luci"})
      assert_true(has_code(report, "901"), "expected a 901, got " .. codes(report))
   end)

   it("keeps the finding line and column identical to the validly-written file", function()
      local bad = 'local s = "<\\/a>"\nos.execute("x " .. http.formvalue("h"))\n'
      local good = 'local s = "<\\\\/a>"\nos.execute("x " .. http.formvalue("h"))\n'
      local function loc(report)
         for _, finding in ipairs(report) do
            if finding.code == "709" then return finding.line .. ":" .. finding.column end
         end
         return nil
      end
      local bad_loc = loc(api.check_source(bad, {std = "luci"}))
      local good_loc = loc(api.check_source(good, {std = "luci"}))
      assert_true(bad_loc ~= nil, "expected a 709 in the normalised file")
      assert_equal(bad_loc, good_loc, "location must survive normalisation")
   end)
end)
