local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_no_match = harness.assert_equal, harness.assert_true, assert_no_match

local api = require "luasec.api"

-- Every code a report carries, sorted and joined, for exact-match assertions.
local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

-- The three bytes a UTF-8 byte order mark is made of.
local BOM = string.char(239, 187, 191)

describe("a source file that opens with a byte order mark", function()
   it("is parsed, not reported as a parse failure", function()
      -- A BOM is encoding metadata, not source, and Lua will not accept one at
      -- the start of a chunk. Reported as 901 it would tell an operator their
      -- file is broken when a Lua 5.4 interpreter loads it, and it would cost
      -- every finding in the file: the analysis degrades to a lexical scan.
      local report = api.check_source(BOM .. [[
local function ping(host)
   os.execute("ping -c1 " .. http.formvalue(host))
end

return ping
]], {std = "+luci"})

      assert_no_match(codes(report), "901",
         "a file with a BOM is not a file that failed to parse")
      assert_equal(codes(report), "709",
         "the file is analyzed in full, so the taint in it is found")
   end)

   it("keeps every column on line one in the right place", function()
      -- The mark is removed before the lexer runs, because the line offsets
      -- every finding is located with are derived from the text the lexer saw.
      -- Removing three bytes afterwards would shift every column on line one.
      local report = api.check_source(BOM .. [[os.execute("ping -c1 " .. http.formvalue("h"))
]], {std = "+luci"})

      local found = report[1]
      assert_true(found ~= nil, "expected a finding")
      assert_equal(found.line, 1, "the finding is on line one")
      assert_equal(found.column, 1, "os.execute starts at column one, BOM or not")
   end)

   it("leaves a file without a mark untouched", function()
      local report = api.check_source([[
local function ping(host)
   os.execute("ping -c1 " .. http.formvalue(host))
end

return ping
]], {std = "+luci"})

      assert_equal(report[1].line, 2, "the same source without a mark locates the same")
      assert_equal(report[1].column, 4, "os.execute is at column four on line two")
   end)
end)
