local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luasec.api"

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

local SINK = [[
local function go(host)
   os.execute("ping " .. http.formvalue("host"))
end
]]

describe("in-source directives", function()
   it("reports the finding when no directive is present", function()
      assert_equal(codes(api.check_source(SINK)), "709")
   end)

   it("silences a finding with -- luasec: ignore on the line above", function()
      local report = api.check_source([[
local function go(host)
   -- luasec: ignore 709
   os.execute("ping " .. http.formvalue("host"))
end
]])
      assert_equal(codes(report), "")
   end)

   it("applies a directive only from its own line onward", function()
      local report = api.check_source([[
local function first(host)
   os.execute("ping " .. http.formvalue("a"))
end
-- luasec: ignore 709
local function second(host)
   os.execute("ping " .. http.formvalue("b"))
end
]])
      assert_equal(#report, 1, "only the call before the directive is reported")
      assert_equal(report[1].line, 2, "the surviving finding is the call above the directive")
   end)

   it("honours a code pattern with a character class", function()
      local report = api.check_source([[
local function go(host)
   -- luasec: ignore 7[0-9][0-9]
   os.execute("ping " .. http.formvalue("host"))
end
]])
      assert_equal(codes(report), "")
   end)

   it("honours a name after a colon", function()
      local report = api.check_source([[
local function go(host)
   -- luasec: ignore 709:os.execute
   os.execute("ping " .. http.formvalue("host"))
end
]])
      assert_equal(codes(report), "")
   end)

   it("does not silence a different sink from the same code", function()
      local report = api.check_source([[
local function go(host)
   -- luasec: ignore 709:io.popen
   os.execute("ping " .. http.formvalue("host"))
end
]])
      assert_equal(codes(report), "709")
   end)

   it("lets -- luasec: enable override a command line ignore", function()
      local report = api.check_source([[
local function go(host)
   -- luasec: enable 709
   os.execute("ping " .. http.formvalue("host"))
end
]], {ignore = {"709"}})
      assert_equal(codes(report), "709", "an in-source enable must win over --ignore")
   end)

   it("reports a malformed directive instead of ignoring it", function()
      local report = api.check_source([[
local function go(host)
   -- luasec: nonsense 709
   os.execute("ping " .. http.formvalue("host"))
end
]])
      assert_match(codes(report), "012", "a typo must not look like a suppression")
   end)

   it("reports a directive that names no code", function()
      local report = api.check_source([[
local function go(host)
   -- luasec: ignore
   os.execute("ping " .. http.formvalue("host"))
end
]])
      assert_match(codes(report), "012")
   end)

   it("works through the CLI as well", function()
      local out, code = harness.cli({ "test/fixtures/inline/ignored.lua" })
      assert_equal(code, 0, out)
      assert_match(out, "0 findings", out)
   end)
end)

describe("a directive the analyzer cannot read", function()
   it("reports it as unreadable rather than raising", function()
      local api = require "luasec.api"
      local handle = assert(io.open("test/fixtures/malformed_directive.lua", "r"))
      local report = api.check_source(handle:read("*a"), {std = "luajit"})
      handle:close()

      local unreadable, kept = 0, 0
      for _, finding in ipairs(report) do
         if finding.code == "012" then unreadable = unreadable + 1 end
         if finding.code == "701" then kept = kept + 1 end
      end

      -- A suppression we could not read is not a suppression we applied, so
      -- the finding it was meant to hide is still reported - and the operator is
      -- told their directive did not work.
      assert_true(unreadable >= 1, "the unreadable directive is reported: " ..
         tostring(#report) .. " findings")
      assert_equal(kept, 1, "the finding the directive would have hidden is kept")
   end)
end)

describe("every malformed code pattern", function()
   it("completes the scan and never hides a finding", function()
      local api = require "luasec.api"
      -- The property that matters, whichever way Lua reads the pattern: a
      -- suppression that cannot be read must not hide what it named. Handing
      -- the operator's text to string.match unguarded raised "malformed
      -- pattern" and killed the whole scan, so a file whose only content was a
      -- typo cost every other file its findings.
      local forms = {"[708", "70(", "70)", "70%", "7[0", "70[0-9", "%", "%1",
                     "701:[bad", "701:(", "701:)", "701:%"}
      for _, form in ipairs(forms) do
         local source = "-- luasec: ignore " .. form .. "\nos.execute(cmd)\n"
         local report = api.check_source(source, {std = "luajit"})

         local kept = false
         for _, finding in ipairs(report) do
            if finding.code == "701" then kept = true end
         end
         assert_true(kept,
            "a broken suppression never hides the finding: " .. form)
      end
   end)

   it("reports the forms Lua rejects outright as 012", function()
      local api = require "luasec.api"
      local report = api.check_source("-- luasec: ignore [708\nos.execute(cmd)\n",
         {std = "luajit"})
      local unreadable = false
      for _, finding in ipairs(report) do
         if finding.code == "012" then unreadable = true end
      end
      assert_true(unreadable, "an unreadable directive is reported, not guessed at")
   end)

   it("still applies a pattern it can read", function()
      local api = require "luasec.api"
      for _, form in ipairs({"701", "70[0-9]", "701:os.execute"}) do
         local report = api.check_source(
            "-- luasec: ignore " .. form .. "\nos.execute(cmd)\n", {std = "luajit"})
         assert_equal(#report, 0,
            "a valid suppression still suppresses: " .. form)
      end
   end)
end)

describe("a suppression pattern with too many repetition quantifiers", function()
   it("is rejected as 012 before it can backtrack against the 127-byte probe", function()
      -- Issue #66: a pattern with more than three repetition quantifiers
      -- (-, *, +, ?) can force Lua's matcher into exponential backtracking
      -- against the 127-byte probe that is_valid_pattern uses to sanity-check
      -- readability. `-- luasec: ignore .-.-.-.-.-` costs ~127^k where k is the
      -- number of quantifiers; k=4 takes seconds, k=5 never returns. The
      -- pattern must be refused before string.match is ever called, treated as
      -- unreadable, and the finding it would have hidden stays reported.
      local source = "-- luasec: ignore .-.-.-.-.-.\nos.execute(cmd)\n"
      local start = os.clock()
      local report = api.check_source(source, {std = "luajit"})
      local elapsed = os.clock() - start

      assert_true(elapsed < 1,
         ("the probe must not backtrack on a too-complex pattern: %.3fs"):format(elapsed))

      local unreadable, kept = false, false
      for _, finding in ipairs(report) do
         if finding.code == "012" then unreadable = true end
         if finding.code == "701" then kept = true end
      end
      assert_true(unreadable,
         "the too-complex pattern is reported as unreadable: " .. codes(report))
      assert_true(kept,
         "the finding the rejected suppression would have hidden is still reported: "
         .. codes(report))
   end)

   it("still suppresses with patterns at or under the quantifier and length bounds", function()
      -- Patterns with three or fewer quantifiers and 64 bytes or fewer must
      -- still work as before: the guard only refuses what is too complex to run.
      local forms = {"70[0-9]", "701:os%.execute"}
      for _, form in ipairs(forms) do
         local report = api.check_source(
            "-- luasec: ignore " .. form .. "\nos.execute(cmd)\n", {std = "luajit"})
         assert_equal(#report, 0,
            "a bounded suppression still suppresses: " .. form
            .. " left " .. codes(report))
      end
   end)
end)
