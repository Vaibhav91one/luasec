local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luasec.api"

-- The README is the product's only front door: someone decides whether to trust
-- this tool by reading it. A number in it that has quietly stopped being true
-- is worse than no number, so the ones that can be checked from the tree are
-- checked. This is the same failure that ran three times in docs/precision.md,
-- in the document people are most likely to quote.
--
-- Six stale figures reached `main` through this file while CI was green (#273),
-- and every one of them was somewhere a gate was not looking. Four were caught
-- only because the headline is gated below, which is the point: the headline had
-- a gate and the per-code rows beside it did not, so a number nobody checked sat
-- four lines under a number that was checked and went stale anyway.
--
-- It cannot check a judgment. "Beta", "does not follow a return value" and
-- "a scan root is bounded" are claims for a reader to weigh, not assertions to
-- enforce, and a spec that pretended otherwise would only make this file
-- mechanical.

local function read(path)
   local handle = assert(io.open(path, "r"))
   local text = handle:read("*a")
   handle:close()
   return text
end

-- ---------------------------------------------------------------------------
-- Telling a per-code row from a derived one.
--
-- The measurement table carries three kinds of figure and they are not the same
-- kind of claim:
--
--   per-code   `| `709` untrusted data -> execution | 23 |`
--              one rule, how many findings it reported. The golden has this.
--   derived    `| Severity | 24 critical, 523 high, 34 medium, 30 low |`
--              and `| Findings | **611** across 706 scanned files (21%) |`
--              a mix over many codes, and a denominator. The golden carries a
--              total and a file count but NOT a severity breakdown and NOT the
--              145 files that carry a finding, so a parser that demands every
--              row's number appear in `golden.codes` fails on rows that are
--              correct, and then the fix is to weaken the gate rather than to
--              correct the row - which is the failure mode this whole issue is
--              about.
--
-- So the discriminator is the shape of the ROW, not the number in it, and it is
-- deliberately narrow:
--
--   * the row is inside the measurement table (a `|`-delimited line between the
--     table's header rule and the next prose paragraph), and
--   * the row's first cell contains a backticked three-digit code in the exact
--     form the catalogue prints them: `709`, not `709-712`, not `701 - 712`.
--
-- A code that is not registered - `701-712`, `012`, `901-904` written as ranges -
-- does not match, which is what keeps the "Category / Codes" table further up the
-- README out of this. A bare `| 709 |` with no backticks is prose and does not
-- match. Both of those exclusions are asserted in the spec below rather than
-- assumed, because a discriminator that quietly starts matching more than the
-- author intended is how a gate gets turned off by accident.
--
-- What the discriminator deliberately does NOT do is read the last cell and
-- require it to be an integer. Two of the rows above do not end in a bare
-- integer - the `747` row ends in a sentence, and the Findings row ends in a
-- percentage - and a parse built on "the number at the end of the row" is wrong
-- on both of them. Matching the row's LABEL is the only thing that separates
-- "a count for rule 709" from "a count over everything".
-- ---------------------------------------------------------------------------

local GOLDEN = "scripts/precision-golden.lua"

local function frozen()
   local chunk = assert(loadfile(GOLDEN), GOLDEN .. " does not load")
   return chunk()
end

-- The rows of the README's measurement table, as {label = ..., numbers = {...}}.
--
-- Reads from the `## Measured behaviour` heading and stops at the first line
-- that is not a table row, so a second table further down the README cannot
-- contribute a row to this one. Every table row in that span is collected,
-- including the ones the cases below expect to IGNORE, because the point of
-- returning them all is that the cases decide which ones are per-code.
local function measurement_rows()
   local text = read("README.md")
   local at = assert(text:find("## Measured behaviour", 1, true),
      "README.md has no `## Measured behaviour` section, so the measurement "
         .. "table this reads is gone")
   local body = text:sub(at)
   -- The table's header row is `| | |`; the rule under it is `| --- | --- |`.
   local rows = {}
   local in_table = false
   for line in (body .. "\n"):gmatch("(.-)\n") do
      if line:match("^|") and not line:match("^|%s*|") then
         if line:match("^|%s*%-+%s*|") or line:match("^|%s*%-+") then
            in_table = true          -- the rule: rows start after it
         elseif in_table then
            rows[#rows + 1] = line
         end
      elseif in_table then
         break                        -- first non-row line ends the table
      end
   end
   assert_true(#rows > 0,
      "the measurement table in README.md has no rows; the parser below would "
         .. "pass on an empty table and report success")
   return rows
end

-- Is this row a per-code row? Returns the code if so, nil if not.
--
-- Backtick-wrapped exactly-three-digit code in the FIRST cell. A range
-- (`701-712`), an unregistered code, and a bare number with no backticks are
-- all rejected, which is what makes the Category/Codes table above the
-- measurement table a non-participant.
local function per_code(row)
   local label = row:match("^|([^|]*)")
   if not label then return nil end
   local code = label:match("`(%d%d%d)`")
   if not code then return nil end
   return tonumber(code)
end

local function labelled(rows, want)
   for _, row in ipairs(rows) do
      if row:match("^|%s*" .. want) then return row end
   end
   return nil
end

describe("the README", function()
   it("counts the rule catalogue correctly", function()
      local text = read("README.md")
      local claimed = assert(tonumber(text:match("(%d+) registered rule codes")),
         "the README does not say how many rule codes there are")
      assert_equal(claimed, #api.rule_catalogue(),
         "the README says " .. claimed .. " rule codes; the catalogue has "
            .. #api.rule_catalogue())
   end)

   it("documents only commands that exist", function()
      -- A build instruction that has been renamed is worse than no
      -- instruction, because a reader follows it and concludes the tool is
      -- broken. Every `make X` the README names has to be a real target.
      local makefile = read("Makefile")
      local text = read("README.md")

      for target in text:gmatch("make ([%w%-]+)") do
         -- A target line is `name:` at the start of a line, and this project
         -- uses one dash for the gate's name on the command line and one in
         -- the rule itself, so the target is matched literally.
         -- A PLAIN find. In a Lua pattern the dash in `ci-verify` is a lazy
         -- quantifier applied to the `i` before it, so the pattern does not match
         -- the target it is looking for - and two of this project's targets have
         -- a dash in the name.
         local defined = makefile:find("\n" .. target .. ":", 1, true) ~= nil
         assert_true(defined, "the README says `make " .. target
            .. "` and the Makefile has no such target")
      end
   end)

   it("quotes the same measurement the precision gate checks", function()
      -- The headline number. docs/precision.md and scripts/precision-golden.lua
      -- are both checked against each other and against a real run; the README
      -- quotes the same figure and is the one most likely to be read.
      local text = read("README.md")
      local golden = dofile("scripts/precision-golden.lua")
      local claimed = assert(tonumber(text:match("Findings | %*%*(%d+)%*%* across")),
         "the README does not state the finding count it measured")
      assert_equal(claimed, golden.total,
         "the README quotes " .. claimed .. " findings; the frozen measurement is "
            .. golden.total)
   end)

   it("states a per-code row in the measurement table the same way the golden does", function()
      -- The gate #273 is for, and the narrow one. Every row of the README's
      -- measurement table whose first cell names a rule code is held to
      -- scripts/precision-golden.lua, in both directions: a count the golden
      -- does not have, and a count that disagrees with the one it does.
      --
      -- Both directions matter. The first catches a row for a rule the run no
      -- longer reports; the second is the one this issue was opened for - a row
      -- that stayed at its old number through a PR that moved the code.
      local golden = frozen()
      local stale, unknown, checked = {}, {}, 0

      for _, row in ipairs(measurement_rows()) do
         local code = per_code(row)
         if code then
            if golden.codes[code] == nil then
               unknown[#unknown + 1] = code
            else
               checked = checked + 1
               -- The count is the FIRST integer in the rest of the row, not the
               -- last cell parsed as an integer. The 747 row's cell is
               -- "**15, and all 15 are false positives** - see below", and a
               -- cell that has to be entirely a number skips that row while
               -- appearing to cover it.
               local cell = row:match("^|[^|]*|(.*)$")
               local claimed = cell and tonumber(cell:match("(%d+)"))
               if claimed == nil then
                  -- A per-code row whose cell carries no number at all cannot be
                  -- compared, and quietly skipping it is how a real count
                  -- escapes a gate that claims to hold it.
                  stale[#stale + 1] = "code " .. code .. ": the row carries no "
                     .. "count to compare: " .. row
               elseif claimed ~= golden.codes[code] then
                  stale[#stale + 1] = "code " .. code .. ": the README says "
                     .. claimed .. ", the frozen measurement says "
                     .. golden.codes[code] .. " (" .. row .. ")"
               end
            end
         end
      end

      assert_equal(#unknown, 0,
         "the README's measurement table has a row for code(s) "
            .. table.concat(unknown, ", ") .. ", which "
            .. GOLDEN .. " does not measure. A per-code count here has to be a "
            .. "count the run actually reported")
      assert_equal(#stale, 0,
         #stale .. " per-code row(s) in README.md disagree with " .. GOLDEN
            .. ":\n  " .. table.concat(stale, "\n  "))
      -- A gate that found nothing because it matched nothing is the failure
      -- this issue is about wearing a different hat, so the number of rows it
      -- actually compared is part of what it asserts.
      assert_true(checked > 0,
         "no per-code row in README.md's measurement table was compared against "
            .. GOLDEN .. ". If the rows were removed on purpose, say so in the "
            .. "spec; if the parser stopped matching them, this gate is now "
            .. "vacuous and will stay green through the next stale figure")
   end)

   it("reads the two derived rows as derived, not as per-code counts", function()
      -- The negative half, and the half that keeps the case above honest. The
      -- measurement table also carries a severity mix and a findings-and-files
      -- row; neither is a per-code count and the golden carries neither. If the
      -- parser matched them it would fail on rows that are correct, and the
      -- tempting fix would be to teach the golden to carry a severity split -
      -- which is a different issue's file and would make the gate depend on the
      -- thing it is supposed to check.
      local rows = measurement_rows()

      assert_true(labelled(rows, "Severity") ~= nil,
         "the README's measurement table no longer has a Severity row, so this "
            .. "case cannot tell a derived row from a per-code one")
      assert_equal(per_code(labelled(rows, "Severity")), nil,
         "the Severity row is being read as a per-code row. It is a mix over "
            .. "every code and " .. GOLDEN .. " carries no such split")

      local findings = assert(labelled(rows, "Findings"),
         "the README's measurement table has no Findings row")
      assert_equal(per_code(findings), nil,
         "the Findings row is being read as a per-code row. It is a total over "
            .. "every code and a denominator, which is golden.total, not "
            .. "golden.codes")
   end)

   it("does not read a code range in the catalogue table as a per-code row", function()
      -- The README has a second table, above the measurement one, whose "Codes"
      -- column holds ranges like 701-712 and 901-904. A parser that keyed on
      -- "a three-digit number in the row" would pull those in and demand a
      -- count for a range, which is not a thing a run reports.
      --
      -- This is asserted on the shape rather than on the README's contents, so
      -- it holds whatever the catalogue table says next year.
      assert_equal(per_code("| `exec` | command execution and dynamic code sinks | 701-712 |"), nil,
         "a code range in the catalogue table is being read as a single code")
      assert_equal(per_code("| `meta` | parse, dialect and coverage-gap codes | 012, 901-904 |"), nil,
         "a comma-separated code list is being read as a single code")
      assert_equal(per_code("| `709` untrusted data → execution | 23 |"), 709,
         "a backticked three-digit code in the first cell is not recognised as a "
            .. "per-code row, which is the one form this gate does match")
   end)

   it("states the exit codes the CLI actually defines", function()
      local text = read("README.md")
      for _, code in ipairs({"0", "1", "2", "3"}) do
         assert_true(text:find("`" .. code .. "`", 1, true) ~= nil,
            "the README does not document exit code " .. code)
      end
   end)

   it("does not claim to cover what the tool documents as out of scope", function()
      -- The failure mode this file exists to prevent is a README that grows more
      -- confident than the code. If the out-of-scope list in
      -- docs/architecture.md gains an item, the README has to acknowledge it.
      local text = read("README.md")
      local scope = read("docs/architecture.md")
      local out_of_scope = scope:match("## What is out of scope(.*)$")

      assert_true(out_of_scope ~= nil, "the out-of-scope section is where it says it is")
      for _, limit in ipairs({"return value", "decompiled"}) do
         if out_of_scope:find(limit, 1, true) then
            assert_true(text:find(limit, 1, true) ~= nil,
               "docs/architecture.md lists '" .. limit .. "' as out of scope and "
                  .. "the README does not mention it")
         end
      end
   end)
   it("documents the terminal options a person types", function()
      local text = read("README.md")
      for _, flag in ipairs({"--interactive", "--no-interactive", "--view doctor", "--progress"}) do
         assert_true(text:find(flag, 1, true) ~= nil,
            "the README does not document " .. flag)
      end
   end)
   it("describes the interactive selector, the findings browser and the hand-off", function()
      local text = read("README.md")
      for _, phrase in ipairs({"(Recommended)", "findings browser", "hand-off submenu", "Scanned N files"}) do
         assert_true(text:find(phrase, 1, true) ~= nil,
            "the README does not mention " .. phrase)
      end
   end)
end)
