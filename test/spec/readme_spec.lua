local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luadoctor.api"

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
-- What this does not check, stated rather than implied.
--
-- It reads the measurement TABLE and nothing else. The README also carries
-- per-code figures in prose - the collapsed "Why the table stays honest" block
-- says the OpenResty entries "gave it 15" for 747 - and those can drift exactly
-- as the rows did, with every case here green. That is a real gap and this is
-- not the change that closes it.
--
-- It is not closed here for the same reason docs/precision.md's prose gate was
-- built separately in #258: holding prose to a number needs a claim grammar that
-- tells a live figure from a historical one, and that grammar exists in
-- test/spec/precision_spec.lua. Duplicating a second, weaker copy of it here
-- would make two documents disagree about what counts as history, and the one
-- that is wrong would be this one.
--
-- What this change does instead is remove the rows that had no such grammar to
-- protect them, and state in the README itself that a per-code count lives in
-- docs/precision.md. The rule that stops a future contributor from retyping a
-- row is the sentence; the gate only makes the sentence enforceable.
-- ---------------------------------------------------------------------------
--
-- ---------------------------------------------------------------------------
-- Telling a per-code row from a derived one.
--
-- The measurement table carries two kinds of figure, and they are not the same
-- kind of claim:
--
--   per-code   `| `709` untrusted data -> execution | 23 |`
--              one rule, how many findings it reported. The golden has this.
--   derived    `| Severity | 24 critical, 523 high, 34 medium, 30 low |`
--              and `| Findings | **611** across 706 scanned files |`
--              a mix over many codes, and a denominator. The golden carries a
--              total and a file count but NOT a severity breakdown, so a parser
--              that demands every row's number appear in `golden.codes` fails on
--              rows that are correct, and then the fix is to weaken the gate
--              rather than to correct the row - which is the failure mode this
--              whole issue is about.
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
-- require it to be a bare integer. The 747 row this table used to carry ended in
-- a sentence - "**15, and all 15 are false positives** - see below" - and a
-- parse built on "the number at the end of the row" skips that row while
-- appearing to cover it. Matching the row's LABEL is the only thing that
-- separates "a count for rule 709" from "a count over everything", and it does
-- not care what the other cell happens to hold.
-- ---------------------------------------------------------------------------

local GOLDEN = "scripts/precision-golden.lua"

local function frozen()
   local chunk = assert(loadfile(GOLDEN), GOLDEN .. " does not load")
   return chunk()
end

-- The body rows of the README's measurement table, as raw markdown lines.
--
-- Reads from the `## Measured behaviour` heading and stops at the first line
-- that is not a table row, so a second table further down the README cannot
-- contribute a row to this one, and the catalogue table above cannot either.
-- Every row in that span is returned, including the ones the cases below expect
-- to IGNORE, because the point of returning them all is that the cases decide
-- which ones are per-code.
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

   it("quotes the headline and the denominator the same way the precision gate does", function()
      -- The two figures the table keeps. Both are checked against
      -- scripts/precision-golden.lua, and both are checked rather than quoted,
      -- because #273 exists because four of the six stale figures that reached
      -- `main` through this file were caught here and nowhere else.
      --
      -- scanned_files is not corpus_files and the difference is not noise: the
      -- corpus collects 691 `.lua` files and the walker selects 706 paths from
      -- them. Both are claims a reader quotes, so both are held.
      local text = read("README.md")
      local golden = frozen()

      local total, files = text:match(
         "Findings | %*%*(%d+)%*%* across (%d+) scanned files")
      total = assert(tonumber(total),
         "the README does not state the finding count and the file count it "
            .. "measured, in the form this case reads")
      files = assert(tonumber(files),
         "the README does not say how many files it scanned")

      assert_equal(total, golden.total,
         "the README quotes " .. total .. " findings; the frozen measurement is "
            .. golden.total)
      assert_equal(files, golden.scanned_files,
         "the README quotes " .. files .. " scanned files; the frozen "
            .. "measurement analyzed " .. golden.scanned_files)
   end)

   it("quotes as many collected files as the corpus holds", function()
      -- The sentence above the table names the corpus. It read 964 while the
      -- table three lines below it read 706, and nothing noticed: 964 was the
      -- scanned count before #288 stopped the walker reading Perl test specs,
      -- and it is neither of the two numbers the golden holds now.
      local text = read("README.md")
      local golden = frozen()
      local claimed = assert(tonumber(text:match("Over %*%*(%d+) files%*%*")),
         "the README does not say how many files the corpus collected")
      assert_equal(claimed, golden.corpus_files,
         "the README quotes " .. claimed .. " collected files; the frozen "
            .. "measurement collected " .. golden.corpus_files)
   end)

   it("carries no per-code count, because docs/precision.md is the only place one appears", function()
      -- The gate #273 asked for, in the form the decision in that issue
      -- actually took. The per-code rows were removed rather than gated, and the
      -- reason is that gating them would have certified them: they were four of
      -- the twenty codes the run reports, they showed nothing above 25, and they
      -- omitted `707` - 346 findings against 265 from all nineteen other codes
      -- put together. Holding those four to the golden would have kept a table
      -- that is true of each row and false about the shape of the measurement.
      --
      -- So the rule is structural: the README states the totals and the
      -- denominator; docs/precision.md states a per-code count. This case fails
      -- the moment a per-code row comes back, which is the whole point - the
      -- failure is loud, and it says where the number belongs.
      local per_code_rows = {}
      for _, row in ipairs(measurement_rows()) do
         local code = per_code(row)
         if code then per_code_rows[#per_code_rows + 1] = row end
      end

      assert_equal(#per_code_rows, 0,
         "README.md's measurement table carries "
            .. #per_code_rows .. " per-code row(s), and docs/precision.md is the "
            .. "only place a current per-code total appears:\n  "
            .. table.concat(per_code_rows, "\n  ")
            .. "\n  Link to it instead. If a per-code row is genuinely wanted "
            .. "here, this is the case to argue with.")
   end)

   it("keeps the two derived rows, so the table is still worth reading", function()
      -- The negative half of the case above, and the one that stops it being
      -- satisfied by deleting the whole table. A gate forbidding per-code rows
      -- is also satisfied by an empty one, which would remove the measurement
      -- from the product's front door and call it hygiene. The totals and the
      -- severity mix are what the README is for; they are the figures a person
      -- deciding whether to trust this tool reads first.
      local rows = measurement_rows()
      for _, want in ipairs({"Findings", "Severity"}) do
         assert_true(labelled(rows, want) ~= nil,
            "README.md's measurement table has no " .. want .. " row. It carries "
               .. "the totals and the denominator; deleting those is not what "
               .. "this gate is for")
      end
   end)

   it("would still catch a per-code row put back", function()
      -- Anti-vacuity, and the reason the case above can be trusted with zero
      -- per-code rows in the document. A gate that matches nothing passes; this
      -- one is asserted against the exact rows that were removed, so if the
      -- parser ever stops recognising them this fails instead of going quiet
      -- through the next stale figure.
      --
      -- These are the four rows verbatim as they stood on `main` before this
      -- change, including the 747 row whose cell is a sentence rather than a
      -- number - the one a `| N |` parse would have skipped while looking like
      -- it had covered it.
      local removed = {
         {"| `709` untrusted data → execution | 23 |", 709},
         {"| `724` execution sink exposed as an RPC handler | 25 |", 724},
         {"| `708` exposed sink, input not visible in this file | 22 |", 708},
         {"| Hardcoded credentials (`747`) | **15, and all 15 are false positives** — see below |", 747},
      }
      for _, row in ipairs(removed) do
         assert_equal(per_code(row[1]), row[2],
            "the parser no longer recognises " .. row[1] .. " as a per-code row "
               .. "for " .. row[2] .. ". The gate that forbids those rows would "
               .. "pass without them, which is the failure this case exists to "
               .. "prevent")
      end
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

   -- #294: the collapsed OpenResty paragraph carried a present-tense per-code count ("gave it 15")
   -- that nothing gated. It is written as history instead, which needs no gate, and the live figure
   -- is pointed at docs/precision.md, where the claim grammar of precision_spec does gate it.
   it("states the OpenResty 747 count as history and points at docs/precision.md", function()
      local text = read("README.md")
      local paragraph = text:match("On `747`, as history:(.-)\n\n")
      assert_true(paragraph ~= nil, "the README's 747 paragraph is no longer written as history")
      assert_true(paragraph:find("#262", 1, true) ~= nil, "the history is not tied to the change that made it (#262)")
      assert_true(paragraph:find("docs/precision.md", 1, true) ~= nil,
         "the live per-code figure is not pointed at docs/precision.md")
      assert_true(paragraph:find("RFC%-mandated") == nil, "the unsupported RFC-mandated claim is back")
   end)
end)
