-- The scope of an in-source `-- luasec:` suppression: which findings it silences
-- and, just as important, which findings it must leave alone.
--
-- Every case here is a defect that was live in this codebase. The common theme is
-- the one that matters for a security tool: a suppression that does more than the
-- operator asked for hides findings, and a suppression that does less is a
-- coverage gap nobody was told about. Both directions have to be pinned.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_no_match = harness.assert_equal, harness.assert_true, harness.assert_no_match

local api = require "luasec.api"

-- The distinct codes a report carries, sorted and joined. A set, not a multiset:
-- what a scoping test asks is which codes are present at all, and the number of
-- findings is asserted where it is the answer.
local function codes(report)
   local seen, out = {}, {}
   for _, finding in ipairs(report) do
      if not seen[finding.code] then
         seen[finding.code] = true
         out[#out + 1] = finding.code
      end
   end
   table.sort(out)
   return table.concat(out, ",")
end

-- Every line a report places a finding on, sorted and joined. The count of
-- findings is not enough for a scoping test: the bug was never "the wrong
-- number", it was "the wrong lines", with the right number of them.
local function lines(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.line end
   table.sort(out)
   return table.concat(out, ",")
end

-- Does a report carry a finding with this code?
local function has(report, code)
   for _, finding in ipairs(report) do
      if finding.code == code then return true end
   end
   return false
end

-- The message of the first finding with this code, or "".
local function message_of(report, code)
   for _, finding in ipairs(report) do
      if finding.code == code then return finding.message or "" end
   end
   return ""
end

-- Lines of filler, so "still file-wide" is a claim about the whole file and not
-- about the two lines next to the directive.
local function filler(count)
   local out = {}
   for i = 1, count do out[i] = "-- line " .. i end
   return out
end

-- A scratch directory under TMPDIR. Nothing in a spec may write inside the repo:
-- a whole-program spec wrote its fixtures to relative paths once and they were
-- committed with the spec.
local scratch_serial = 0
local function scratch_dir(tag)
   scratch_serial = scratch_serial + 1
   local dir = os.getenv("TMPDIR") or "/tmp"
   dir = dir:gsub("/$", "")
   dir = ("%s/luasec_directive_%s_%d_%d"):format(dir, tag, os.time(), scratch_serial)
   os.execute("mkdir -p " .. string.format("%q", dir))
   return dir
end

local function write_file(dir, name, text)
   local path = dir .. "/" .. name
   local handle = assert(io.open(path, "w"))
   handle:write(text)
   handle:close()
   return path
end

local function rm(dir)
   os.execute("rm -rf " .. string.format("%q", dir))
end

describe("a suppression between a push and a pop", function()
   it("silences the region and nothing outside it", function()
      -- `push` and `pop` were parsed into the directive list and then never read,
      -- so a pop changed nothing at all: the suppression stayed in force to the
      -- end of the file and the operator got the whole file where they asked for
      -- a region, with nothing in the report to say so. Line 6 is the finding
      -- that has to come back.
      local report = api.check_source(table.concat({
         "os.execute(cmd)",           -- 1
         "-- luasec: push",           -- 2
         "-- luasec: ignore 701",     -- 3
         "os.execute(cmd)",           -- 4  silenced
         "-- luasec: pop",            -- 5
         "os.execute(cmd)",           -- 6  still reported
      }, "\n"))

      assert_equal(codes(report), "701",
         "a push and a pop are markers, not suppressions to be reported")
      assert_equal(#report, 2, "one finding before the push and one after the pop")
      assert_equal(lines(report), "1,6",
         "only the finding inside the region is silenced")
   end)
end)

describe("a suppression with no push or pop in the file", function()
   it("is file-wide: every finding after it, to the end of the file", function()
      -- The scoping work must not turn the ordinary form into a region. A plain
      -- `-- luasec: ignore 701` is how every existing suppression in a firmware
      -- tree is written, and it has always meant "from here on".
      local body = filler(40)
      local report = api.check_source(table.concat({
         "-- luasec: ignore 701",     -- 1
         "os.execute(cmd)",           -- 2
         table.unpack(body),
         "os.execute(cmd)",           -- 44
      }, "\n"))

      assert_equal(#report, 0,
         "a plain suppression reaches the end of the file: " .. codes(report))
   end)
end)

describe("a suppression that opens its own region", function()
   it("holds until the pop, and stops at it", function()
      -- `-- luasec: ignore 701 [push]` is the one-line form of a region: the
      -- suppression carries its own push, so it is scoped from its own line to
      -- the next pop. Line 2 is the finding it must silence and line 4 the one
      -- after the pop that must survive.
      --
      -- FAILS today, and the failure is a defect, not a wrong expectation. The
      -- depth of open regions is counted from the `push` and `pop` lines alone,
      -- so a suppression that carries its own `[push]` is read as scoped and is
      -- then never inside a region: on its own, with no `push` line above it, it
      -- silences nothing at all. It used to silence everything (there was no
      -- scoping), so the one-line form went from too wide to inert, and an
      -- operator who wrote it gets neither the region they asked for nor a 012
      -- telling them so. `open_at` has to count a self-pushing suppression as a
      -- push, not only the markers.
      local report = api.check_source(table.concat({
         "-- luasec: ignore 701 [push]",  -- 1
         "os.execute(cmd)",               -- 2  silenced
         "-- luasec: pop",                -- 3
         "os.execute(cmd)",               -- 4  still reported
      }, "\n"))

      assert_equal(lines(report), "4",
         "the suppression covers its own region and no more")
   end)

   it("is not itself read as a code pattern named push", function()
      -- `[push]` was tokenized as a pattern of its own as well as being taken as
      -- the scope marker, so the suppression went looking for findings whose code
      -- or name was literally "push". A directive that names no code has to say
      -- so - and it can only say so if `[push]` is not one of the patterns it
      -- read, because a pattern that is not a pattern is reported as unreadable.
      local report = api.check_source("-- luasec: ignore [push]\nos.execute(cmd)\n")

      assert_true(has(report, "012"),
         "a directive that names no code is reported: " .. codes(report))
      assert_no_match(message_of(report, "012"), "unreadable",
         "[push] was read as a code pattern Lua cannot read")
      assert_equal(message_of(report, "012"),
         "luasec directive 'ignore' needs at least one code pattern",
         "the diagnostic names the missing pattern, not a bad one")
   end)
end)

describe("a pop with no push above it", function()
   it("is a no-op, and leaves a later suppression file-wide", function()
      -- The depth of open regions must not go negative: a stray pop that counted
      -- as closing a region nobody opened puts every suppression after it
      -- "outside a region", where a scoped-only implementation would read them as
      -- not applying at all. The two sinks below are the whole assertion - a
      -- suppression the operator wrote to silence them has to silence them.
      local report = api.check_source(table.concat({
         "-- luasec: pop",          -- 1
         "-- luasec: ignore 701",   -- 2
         "os.execute(cmd)",         -- 3
         "os.execute(cmd)",         -- 4
      }, "\n"))

      assert_equal(#report, 0,
         "an unmatched pop changes nothing: " .. codes(report))
   end)
end)

describe("a code pattern Lua cannot read", function()
   it("never hides the finding it named, in either half of the pattern", function()
      -- The property is fail-safe, whichever way Lua reads the pattern: a
      -- suppression that cannot be applied is not a suppression, so the finding
      -- it was meant to hide is still reported. Handing the operator's text to
      -- string.match unguarded raised "malformed pattern", and that killed the
      -- whole scan - one line of ordinary Lua in one file cost every other file
      -- in the tree its findings, which is the worst failure a scanner has.
      --
      -- Six malformed forms in the code half and the same six in the name half,
      -- plus the two that name nothing at all. Which of them Lua rejects
      -- outright, which it only rejects when the matcher reaches the broken
      -- token, and which it accepts and simply fails to match is not the
      -- question: a pattern that cannot match matches nothing, and every form
      -- must leave the 701 standing.
      local forms = {"[708", "70(", "70)", "70%", "7[0", "70[0-9", "%", "%1",
                     "701:[708", "701:70(", "701:70)", "701:70%", "701:7[0",
                     "701:70[0-9"}

      for _, form in ipairs(forms) do
         local source = "-- luasec: ignore " .. form .. "\nos.execute(cmd)\n"
         local ok, report = pcall(api.check_source, source)

         assert_true(ok, "a broken suppression must not abort the scan: "
            .. form .. " raised " .. tostring(report))
         assert_true(has(report, "701"),
            "a broken suppression never hides a finding: " .. form
            .. " left " .. codes(report))
      end
   end)
end)

describe("a directive whose pattern names no code", function()
   it("reports -- luasec: ignore : and silences nothing", function()
      -- `ignore :` has an empty code half and an empty name half, so both halves
      -- were skipped and it matched every finding in the file: a suppression
      -- that silenced everything, silently. The sibling case, a bare
      -- `-- luasec: ignore`, was already reported; this form was not.
      local report = api.check_source("-- luasec: ignore :\nos.execute(cmd)\n")

      assert_true(has(report, "012"),
         "a directive that names no code is reported: " .. codes(report))
      assert_true(has(report, "701"),
         "and it silences nothing: " .. codes(report))
   end)
end)

describe("a malformed directive in one file of a tree", function()
   it("reports it in that file only", function()
      -- The channel that carries an unreadable pattern is keyed by line number,
      -- and a line number in one file says nothing about a line number in the
      -- next. Without a per-file reset, a typo in file A reported an unreadable
      -- pattern in every file analyzed after it, so a firmware tree with one
      -- bad directive in one file carried a finding in all of them. The finding
      -- is real, and it belongs to the file that has the typo.
      --
      -- Two malformed patterns, because they reach the channel by different
      -- routes: `[708` is rejected while the directive is read, and `70(` passes
      -- every check a reader can make and only reveals itself when the matcher
      -- reaches the unfinished capture. Both have to stay in file A.
      local dir = scratch_dir("crossfile")
      local a = write_file(dir, "a.lua", table.concat({
         "-- luasec: ignore [708",   -- 1  unreadable while the directive is read
         "-- luasec: ignore 70(",    -- 2  unreadable only when it is used
         "os.execute(cmd)",          -- 3
      }, "\n"))
      local b = write_file(dir, "b.lua", "os.execute(cmd)\n")

      local function per_file(report)
         local seen = {}
         for _, finding in ipairs(report) do
            local name = tostring(finding.file):match("([^/]+)$") or "?"
            seen[name] = seen[name] or {}
            table.insert(seen[name], finding)
         end
         return seen
      end

      local report = api.analyze({a, b}, {})
      local by_file = per_file(report)
      rm(dir)

      assert_equal(codes(by_file["a.lua"] or {}), "012,701",
         "the file with the typo reports it, and keeps the finding it would have hidden")
      assert_equal(codes(by_file["b.lua"] or {}), "701",
         "a file with no directive of its own reports none of them")

      -- Same process, a second run: nothing a run learned may reach the next one.
      local dir2 = scratch_dir("crossfile_again")
      local a2 = write_file(dir2, "a.lua", table.concat({
         "-- luasec: ignore [708",
         "-- luasec: ignore 70(",
         "os.execute(cmd)",
      }, "\n"))
      local b2 = write_file(dir2, "b.lua", "os.execute(cmd)\n")
      local again = per_file(api.analyze({a2, b2}, {}))
      rm(dir2)

      assert_equal(codes(again["b.lua"] or {}), "701",
         "a run in the same process does not inherit the previous run's directive")
   end)
end)

describe("a suppression that is a valid pattern", function()
   it("silences what it names, and only what it names", function()
      -- The other side of the malformed-pattern cases. A guard that swallows
      -- every pattern would pass all of them, so this pins that the two halves
      -- are still consulted: the code half, and the name half after it.
      for _, form in ipairs({"701", "70[0-9]", "701:os.execute"}) do
         local report = api.check_source(
            "-- luasec: ignore " .. form .. "\nos.execute(cmd)\n")
         assert_equal(#report, 0,
            "a valid suppression still suppresses: " .. form .. " left "
            .. codes(report))
      end

      -- A name pattern that names a different sink is not a match, and a
      -- suppression that quietly widened itself to everything of that code would
      -- be indistinguishable from one that worked.
      local report = api.check_source("-- luasec: ignore 701:nosuch\nos.execute(cmd)\n")
      assert_equal(codes(report), "701",
         "a name pattern that does not match silences nothing")
   end)
end)

describe("a code pattern Lua will not read", function()
   it("is reported as 012, once, and still hides nothing", function()
      -- The code half is evaluated against every finding, so a pattern it
      -- rejects is discovered and reported. The name half is only reached when
      -- the code half matches, so a malformed name on a code that matches
      -- nothing is never tried: the case above covers it, and that is the whole
      -- of what can be promised. A pattern Lua accepts and simply fails to match
      -- cannot be detected at all - it is indistinguishable from a valid pattern
      -- that matched nothing - and it is fail-safe, so a suppression written
      -- that way silences nothing rather than everything.
      local forms = {"[708", "70(", "70)", "70%", "7[0", "70[0-9", "%1"}

      for _, form in ipairs(forms) do
         local report = api.check_source(
            "-- luasec: ignore " .. form .. "\nos.execute(cmd)\n")

         assert_true(has(report, "701"),
            "a pattern that cannot be read hides nothing: " .. form
            .. " left " .. codes(report))

         local count = 0
         for _, finding in ipairs(report) do
            if finding.code == "012" then count = count + 1 end
         end
         assert_equal(count, 1,
            "exactly one 012 for an unreadable pattern, not none and not two: "
            .. form .. " gave " .. codes(report))
      end
   end)
end)

describe("a `only` directive whose pattern cannot be read", function()
   it("selects nothing rather than everything, and says so", function()
      -- `only` means "report this and nothing else", so a pattern that cannot
      -- be read leaves the question of what was selected unanswered - and the
      -- answer must not be "nothing", because that reads as "none of your
      -- findings match": a clean report and exit 0 for a file with a hardcoded
      -- root password in it. The directive suppressed the very 012 that reports
      -- it. A selection we cannot read now selects nothing, so everything is
      -- still reported, the 012 is never filtered by any in-source directive,
      -- and the run fails.
      local report = api.check_source([[
-- luasec: only [709
local uci = require("uci")
local t = {}
t.uci = uci.cursor()
t.uci:set("system", "root_password", "R00tPassw0rd-2024")
]], {std = "+openwrt+luci"})

      assert_true(has(report, "012"), "the unreadable directive is reported: " .. codes(report))
      assert_true(has(report, "747"),
         "and it does not select away the credential: " .. codes(report))
   end)

   it("still selects when the pattern is one it can read", function()
      local report = api.check_source([[
-- luasec: only 747
local uci = require("uci")
local t = {}
t.uci = uci.cursor()
t.uci:set("system", "root_password", "R00tPassw0rd-2024")
]], {std = "+openwrt+luci"})

      assert_true(has(report, "747"), "the selection still selects: " .. codes(report))
      assert_true(not has(report, "012"),
         "a readable directive is not reported as unreadable: " .. codes(report))
   end)
end)

describe("an unreadable only-pattern learned from one code reaching another", function()
   it("does not hide a finding whose code the pattern never raises on", function()
      -- The pattern `70(` raises when Lua's matcher reaches the unfinished
      -- capture, which only happens for a code whose text walks up to it -
      -- `string.match("709", "70(")` raises "unfinished capture", but
      -- `string.match("723", "70(")` returns nil without ever reaching it.
      --
      -- A one-pass allows_all that cached unreadable per (code, name) key
      -- learned `is unreadable` from the 709 match and `is not unreadable`
      -- from the 723 match: for the 723, with the only-directive selecting
      -- nothing and the per-key flag clear, it took the "not selected" branch
      -- and suppressed the 723. allows() reads the directive's flag, which the
      -- 709 match set for good, so the 723 is fail-safe too: both the 709 and
      -- the 723 survive the broken selection, and the 012 that names the
      -- problem survives alongside them.
      local report = api.check_source(table.concat({
         "-- luasec: only 70(",                    -- 1
         "local function status(host)",             -- 2
         '   os.execute("ping -c1 " .. http.formvalue(host))', -- 3  709
         "end",                                     -- 4
         'local h = io.open("/etc/shadow", "r")',   -- 5  723
      }, "\n"))

      assert_true(has(report, "012"),
         "the unreadable directive is reported: " .. codes(report))
      assert_true(has(report, "709"),
         "the 70x finding that taught the matcher the pattern was unreadable is reported: "
         .. codes(report))
      assert_true(has(report, "723"),
         "the finding whose code never raised is not hidden by that flag: "
         .. codes(report))
   end)
end)
