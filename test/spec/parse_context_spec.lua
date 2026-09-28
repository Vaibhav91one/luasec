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

describe("a source the later analysis stages reject", function()
   it("reports a duplicate label as a parse failure instead of dying", function()
      -- The parser accepts this and linearize rejects it, by raising a bare
      -- table. Unprotected that is a Lua traceback and no report at all, from
      -- one malformed file in a 562-file rootfs.
      local report = api.check_source([[
goto done
::done::
goto done
::done::
]], {std = "lua54"})

      assert_true(#report > 0, "the file is reported, not dropped")
      assert_equal(codes(report), "901",
         "a file the analysis stages reject is a parse failure, reported as one")
   end)

   it("reports a goto with no visible label as a parse failure", function()
      local report = api.check_source("goto nowhere\n", {std = "lua54"})
      assert_equal(codes(report), "901", "reported, not a crash")
   end)

   it("still analyzes a goto that is well formed", function()
      local report = api.check_source([[
for i = 1, 3 do
   if i == 2 then goto continue end
   os.execute("ping -c1 " .. http.formvalue("h"))
   ::continue::
end
]], {std = "+luci"})

      assert_no_match(codes(report), "901", "a valid goto is not a parse failure")
      assert_equal(codes(report), "709", "the file is analyzed in full")
   end)
end)
