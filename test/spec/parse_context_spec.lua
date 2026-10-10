local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_no_match = harness.assert_equal, harness.assert_true, assert_no_match

local api = require "luadoctor.api"

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

describe("a dialect advisory is not an absence of coverage", function()
   it("does not fail a run that was read in full", function()
      -- 903 reports an API the configured standard does not have - a bitwise
      -- operator under `--std luajit`, say. It is a statement about the profile,
      -- not about what lua-doctor managed to read, so it must not fail a run the
      -- way 901 and 904 do. Treating it as degraded made every tree that uses
      -- `<<` a permanently red gate, with no escape hatch: --ignore 903 removed
      -- the lines but the run still exited 1.
      local report = api.check_source([[
local function pack(a, b)
   return a << 2 | b >> 3, ~a
end

return pack
]], {std = "luajit"})

      local seen = false
      for _, finding in ipairs(report) do
         assert_true(finding.code ~= "901",
            "a dialect advisory is not a parse failure")
         if finding.code == "903" then seen = true end
      end
      assert_true(seen, "the bitwise operators are still reported, as 903")
   end)
end)

describe("deeply nested functions", function()
   it("finishes quickly and reports 904 for 1,000 nested functions", function()
      -- count_nodes budgets node counting, but the budget alone does not bound
      -- the cost of resolve_locals: a Function node inside another is visited
      -- super-linearly there. 1,000 nested functions (~3,000 nodes) used to take
      -- more than 60 seconds and now must finish in under 3 seconds, and report
      -- 904 so the run says its analysis was approximate.
      local src = ""
      for i = 1, 1000 do
         src = src .. "local f" .. i .. " = function() "
      end
      src = src .. "return 1"
      for i = 1, 1000 do
         src = src .. " end"
      end
      src = src .. "\n"

      local started = os.clock()
      local report = api.check_source(src, {})
      local elapsed = os.clock() - started

      assert_true(elapsed < 3,
         "1,000 nested functions took " .. elapsed .. " s, expected under 3 s")
      assert_equal(codes(report), "904",
         "deeply nested functions are flagged as approximate, not dropped")
   end)

   it("analyzes 10 nested functions normally without reporting 904", function()
      -- A shallow nesting is well within resolve_locals's cost and must not trip
      -- the depth bound: the file is analyzed in full, no 904.
      local src = ""
      for i = 1, 10 do
         src = src .. "local f" .. i .. " = function() "
      end
      src = src .. "return 1"
      for i = 1, 10 do
         src = src .. " end"
      end
      src = src .. "\n"

      local report = api.check_source(src, {})
      assert_no_match(codes(report), "904",
         "10 nested functions are not too deep to analyze")
   end)
end)
