local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

-- docs/precision.md is a measurement, and a measurement that is edited by hand
-- stops being one. This has been wrong three times: each time the headline was
-- updated and the per-code table below it was not, so the two described different
-- runs. These cases make the document check itself.
--
-- The check is deliberately dumb. It reads the file as text and adds up the
-- numbers, because that is the only property that drifted and the only one a
-- reader can verify by eye.
--
-- The last three cases are about the half of the document that is not the table,
-- and their reasoning is worth reading before changing them: see "the prose gate"
-- below.

local GOLDEN = "scripts/precision-golden.lua"
local DOC = "docs/precision.md"

local function read_precision_doc()
   local handle = assert(io.open("docs/precision.md", "r"))
   local text = handle:read("*a")
   handle:close()
   return text
end

-- The frozen measurement. precision_golden_spec.lua reads it to hold the table to
-- it; this file reads it to hold the prose to it. Neither re-asserts the other's
-- check: one is about a column of numbers, the other is about sentences.
local function frozen()
   local chunk = assert(loadfile(GOLDEN), GOLDEN .. " does not load")
   local measurement = chunk()
   assert_true(type(measurement) == "table" and type(measurement.codes) == "table",
      GOLDEN .. " must return a table carrying `codes`")
   return measurement
end

-- The counts from the per-code table, in the order the codes appear.
local function table_counts(text)
   local start = assert(text:find("| Code | Count | Assessment |", 1, true),
      "the per-code table is gone")
   local counts = {}
   for code, count in text:sub(start):gmatch("|%s*(%d%d%d)%s[^|]*|%s*(%d+)%s*|") do
      counts[#counts + 1] = {code = code, count = tonumber(count)}
   end
   return counts
end

-- ---------------------------------------------------------------------------
-- The prose gate.
--
-- precision_golden_spec.lua holds the per-code table to the frozen measurement in
-- both directions, and the case above holds the headline. A sentence is held to
-- neither: it has no sibling to compare against, so a per-code figure written
-- into the prose of docs/precision.md drifted with every gate green. Two such
-- sentences reached review, both about 708 and both disagreeing with the
-- measurement (#258).
--
-- The rule enforced here is not "prose may not contain a number". It is the
-- distinction that drift actually turned on:
--
--   live         a sentence claiming what the corpus measures NOW. Its figure
--                has to be the frozen figure, or the sentence is stale.
--   historical  a sentence about a run that has already happened. Its figure is
--                true of that run and stays true of it forever, so it is not
--                checked at all.
--
-- Telling those apart is the whole difficulty, and it cannot be done from the
-- number. "747 was the weakest rule in the catalogue: on this corpus every one
-- of its 17 findings was a false positive" carries a per-code figure that
-- disagrees with the frozen measurement - which says 747 finds nothing at all -
-- and it is correct, because it describes the corpus before 747 was narrowed.
-- Reading the arithmetic would delete the history. So the test is the sentence's
-- own grammar, never its arithmetic:
--
--   historical  the sentence names the run it describes (`#235`), or states it
--               in the past (`was`, `were`).
--   live        anything else.
--
-- and a sentence makes a live claim only where a present-tense count phrase
-- binds a bare figure to a rule code, within a short window. That grammar is
-- narrow on purpose: it is the shape both real sentences were written in, and a
-- wider net would start failing on history, which is worse than passing on prose
-- nobody claimed was live.
--
-- What it does not catch, stated rather than implied: a live figure written so
-- the grammar cannot see it ("all 20 of them are bitwise operators", "20 findings
-- under luajit"). Those are prose claims with no code in the sentence to bind
-- them to. Catching them means a claim grammar rather than a count grammar, and
-- a claim grammar mis-reads history as often as it catches a live figure. The
-- rule that actually closes that gap is the one the document now states: the
-- per-code table is the only place a current count appears, so a future sentence
-- has no reason to carry one. The case that asserts the document says so is the
-- last one here.
-- ---------------------------------------------------------------------------

-- How many tokens may separate a rule code, a present-tense count word, and the
-- figure. Wide enough for "708 is unmoved at 33", narrow enough that "708 is
-- true but mislabelled. All 20 findings..." does not bind across the sentence
-- break.
local WINDOW = 3

-- Words that turn what follows them into a statement about the corpus as it
-- stands. Past tense is absent on purpose: `is_historical` has already excluded
-- those sentences, and "708 was 33 findings" is history however it is worded.
--
-- `at` is absent for the same reason of precision. "708 is unmoved at 33" binds
-- through `is`, with `unmoved at` falling inside the window as filler, and `at`
-- as a marker of its own would bind "29 at 701 and 4 at 704" - two codes in a
-- list - as a claim that 701 found 704 times.
local PRESENT_WORD = {
   is = true, are = true, carries = true, counts = true, finds = true,
   now = true, reads = true, remains = true, reports = true, sits = true,
   stands = true, stays = true, still = true, unmoved = true, currently = true,
}

-- Prose only: no fenced code block, because the document quotes commands and a
-- `jq` line inside one is not making a claim about the corpus, and no table row,
-- because the per-code table is precision_golden_spec.lua's and the corpora table
-- carries no rule code. Inline code spans are dropped for the same reason: a file
-- path or a shell fragment in backticks is quoted material, not a claim.
--
-- A heading is terminated so it cannot merge into the paragraph below it. That
-- matters: a heading is not a sentence, and letting one absorb the next sentence
-- would hand the next sentence the heading's words to be classified by.
local function prose_of(text)
   local kept, in_fence = {}, false
   for line in (text .. "\n"):gmatch("(.-)\n") do
      if line:match("^%s*```") then
         in_fence = not in_fence
      elseif in_fence or line:match("^%s*|") then
         -- dropped
      elseif line:match("^%s*#") then
         kept[#kept + 1] = line .. " ."
      else
         kept[#kept + 1] = line
      end
   end
   return (table.concat(kept, "\n"):gsub("`[^`]*`", " "))
end

-- Sentences, not lines. The document wraps at 80 columns and a claim can straddle
-- the break, and the historical test reads whole sentences, so splitting on
-- newlines would hand half a claim to the classifier with the half that made it
-- live left behind.
local function sentences(prose)
   local out, start = {}, 1
   for i = 1, #prose do
      local c = prose:sub(i, i)
      -- A terminator only ends a sentence when whitespace follows it, so
      -- `system.lua:416`, `openwrt-18.06` and `5.3` stay inside their sentence.
      if (c == "." or c == "!" or c == "?") and prose:sub(i + 1, i + 1):match("%s") then
         local sentence = prose:sub(start, i)
         if sentence:match("%S") then out[#out + 1] = sentence end
         start = i + 1
      end
   end
   local tail = prose:sub(start)
   if tail:match("%S") then out[#out + 1] = tail end
   return out
end

-- Does this sentence describe a run that has already happened?
--
-- Two signals, both sentence-local. Not paragraph-local: the sentence the issue
-- calls the harder class - "708 is unmoved at 33 there", under a heading that
-- says **#225** - is historical and reads as live precisely because the heading
-- is the only thing marking it as the past. Letting a heading vouch for its
-- paragraph would wave that sentence through, which is the case #258 is about.
local function is_historical(sentence)
   return sentence:find("#[0-9]+") ~= nil
      or sentence:find("%f[%a]was%f[%A]") ~= nil
      or sentence:find("%f[%a]were%f[%A]") ~= nil
end

-- Numbers, words, and which of them are the rule codes the measurement knows.
--
-- Strictly left to right: at each position take a word, else a number, else step
-- over the character. Searching ahead for the next letter instead would step
-- straight over the digits at the front of a sentence and lose the very claim
-- this exists to find.
local function tokenize(sentence, golden)
   local tokens, pos = {}, 1
   while pos <= #sentence do
      local a, b = sentence:find("[%a][%w']*", pos)
      if a == pos then
         tokens[#tokens + 1] = {word = sentence:sub(a, b)}
         pos = b + 1
      else
         a, b = sentence:find("%d+", pos)
         if a ~= pos then pos = pos + 1 goto continue end
         local before, after = sentence:sub(a - 1, a - 1), sentence:sub(b + 1, b + 1)
         -- "32,000" is two numbers to a tokenizer and one to a reader, and its
         -- first half is not a finding count.
         local grouped = after == "," and sentence:sub(b + 2, b + 2):match("%d") ~= nil
         local number = grouped and nil or tonumber(sentence:sub(a, b))
         -- A rule code, not a version, a line number, a count, or a PR number.
         -- `#225` is a PR; `lua:170` is a line; neither is a claim about 708.
         local is_code = number ~= nil
            and golden.codes[number] ~= nil
            and before ~= "#" and before ~= ":" and before ~= "."
            and after ~= ":" and after ~= "."
         -- A PR reference is a number a sentence carries, and it is never a
         -- finding count, so it cannot serve as one below. Without this, a
         -- document holding no historical finding counts at all but plenty of
         -- `#225` references would satisfy the history case on PR numbers.
         local is_pr = number ~= nil and before == "#"
         tokens[#tokens + 1] = {num = number, code = is_code and number or nil,
                                 pr = is_pr}
         pos = b + 1
      end
      ::continue::
   end
   return tokens
end

-- Every figure a sentence carries for a rule code, paired as loosely as the
-- sentence allows: any rule code with any bare figure anywhere beside it.
--
-- Deliberately looser than `live_figures`, which binds inside three tokens
-- because a count claim is local and a wide net there would sweep in history.
-- This function only ever asks whether a historical figure EXISTS, and it is used
-- to prove the document still has history. At the tight width it found exactly
-- one sentence in a document full of past figures - "747 was the weakest rule ...
-- every one of its 17 findings" binds at fourteen tokens - so a single reword
-- would have taken the count to zero and failed the case for the wrong reason.
local function carried_figures(sentence, golden)
   local tokens = tokenize(sentence, golden)
   local carried = {}
   for _, token in ipairs(tokens) do
      if token.code then
         for _, other in ipairs(tokens) do
            if other.num and not other.code and not other.pr then
               carried[#carried + 1] = {code = token.code, count = other.num}
               break
            end
         end
      end
   end
   return carried
end

-- Every live figure in one sentence: a rule code, a present-tense count word,
-- and a bare figure, all within the window. Everything else in the prose is
-- either history or a sentence that is not making a claim about a rule's count.
local function live_figures(sentence, golden)
   if is_historical(sentence) then return {} end
   local tokens = tokenize(sentence, golden)
   local bound = {}
   for i, token in ipairs(tokens) do
      if token.code then
         for j = i + 1, math.min(#tokens, i + WINDOW) do
            if PRESENT_WORD[tokens[j].word or ""] then
               for k = j + 1, math.min(#tokens, j + WINDOW) do
                  -- A number the measurement knows as a code is naming another
                  -- rule, not reporting how many findings this one made, and
                  -- `#225` is a PR rather than a count of anything.
                  if tokens[k].num and not tokens[k].code and not tokens[k].pr then
                     bound[#bound + 1] = {code = token.code, count = tokens[k].num}
                     break
                  end
               end
               break
            end
         end
      end
   end
   return bound
end

local function shorten(sentence)
   local flat = sentence:gsub("%s+", " ")
   if #flat <= 140 then return flat end
   return flat:sub(1, 137) .. "..."
end

local function stale_report(figure, measured)
   return "code " .. figure.code .. ": " .. DOC .. " claims " .. figure.count ..
      " findings, and the frozen measurement says " .. measured ..
      ". A sentence about the corpus as it stands now has to agree with " ..
      GOLDEN .. ", or point at the per-code table and name the change instead " ..
      "of repeating its figure:\n    " .. shorten(figure.where)
end

describe("the measured precision document", function()
   it("has a per-code table that sums to the headline", function()
      local text = read_precision_doc()
      local headline = assert(tonumber(text:match("(%d+) findings over")),
         "the headline finding count is missing")

      local rows = table_counts(text)
      assert_true(#rows >= 10, "the table lists the codes measured, got " .. #rows)

      local total = 0
      local seen = {}
      for _, row in ipairs(rows) do
         assert_true(not seen[row.code],
            "code " .. row.code .. " appears twice in the table")
         seen[row.code] = true
         total = total + row.count
      end

      -- The exact number changes whenever a rule changes; the agreement does
      -- not. This is the assertion that would have caught all three of the
      -- previous mistakes.
      assert_equal(total, headline,
         "the per-code table sums to " .. total ..
         " but the headline says " .. headline ..
         "; one of them is stale")
   end)

   it("says how many files it measured, and which of the two numbers that is", function()
      -- 562 is what `make corpus` collects; 566 is what luasec analyzed. The
      -- headline carries the second, because that is the denominator the 146
      -- findings were divided by, and the document says so rather than leaving
      -- a reader to guess which number the headline borrowed from the table.
      local text = read_precision_doc()
      local corpus_files = assert(tonumber(text:match("| %*%*total%*%* | %*%*(%d+)%*%*")),
         "the corpora table has no total")
      local headline_files = assert(tonumber(text:match("(%d+) files")),
         "the headline does not say how many files it measured")
      local golden = frozen()

      assert_equal(headline_files, golden.scanned_files,
         "the headline claims " .. headline_files .. " files; the frozen measurement "
         .. "analyzed " .. golden.scanned_files)
      assert_equal(corpus_files, golden.corpus_files,
         "the corpus table claims " .. corpus_files .. " files; the frozen "
         .. "measurement collected " .. golden.corpus_files)
      assert_true(text:find("luasec selects", 1, true) ~= nil,
         "the document does not say which of the two numbers the headline is")
   end)

   it("gives the command that reproduces the number", function()
      -- A measurement nobody can re-run is an assertion. The command is the
      -- difference between the two, so its absence is a failure.
      local text = read_precision_doc()
      assert_true(text:find("bin/luasec", 1, true) ~= nil,
         "the document does not say how to reproduce the measurement")
   end)

   it("states no present-tense per-code count in prose that the measurement contradicts", function()
      -- The gate #258 exists for. Both sentences it caught said "is <n> findings"
      -- about a rule code, and neither of them had a sibling to compare against,
      -- so the table check above passed while the prose sat there wrong.
      --
      -- A live figure that AGREES with the measurement passes. This is not a
      -- style rule about restating numbers; it is a staleness rule. A sentence
      -- that is right today and reads as a live claim is correct, and deleting it
      -- would lose a reader more than it would protect one.
      local golden = frozen()
      local stale = {}

      for _, sentence in ipairs(sentences(prose_of(read_precision_doc()))) do
         for _, figure in ipairs(live_figures(sentence, golden)) do
            figure.where = sentence
            local measured = golden.codes[figure.code]
            if figure.count ~= measured then
               stale[#stale + 1] = stale_report(figure, measured)
            end
         end
      end

      assert_equal(#stale, 0,
         #stale .. " sentence(s) in " .. DOC .. " state a per-code count for the "
         .. "corpus as it stands now that the frozen measurement contradicts:\n  "
         .. table.concat(stale, "\n  "))
   end)

   it("keeps its historical figures, because a figure about a past run is not drift", function()
      -- The negative half of the case above, and the one that stops it being
      -- satisfied by deleting the past. The document is a record of how the
      -- number got here, and a reader needs "747 used to report 17 findings and
      -- every one was false" more than they need a document that has forgotten
      -- it. The frozen measurement says 747 finds nothing now; that sentence is
      -- still true and says `was`.
      --
      -- So: there must still be prose carrying a per-code figure that
      -- DISAGREES with the measurement, in a sentence the historical test
      -- recognises. Zero such sentences means the history has been rewritten to
      -- be quiet, which is not what this document is for - and it is the failure
      -- mode a laxer version of this gate would have, quietly.
      --
      -- It does not re-assert the live gate. `live_figures` returns nothing for
      -- a historical sentence by construction, so comparing it here would be a
      -- check that cannot fail.
      local golden = frozen()
      local historical, past = 0, 0

      for _, sentence in ipairs(sentences(prose_of(read_precision_doc()))) do
         if is_historical(sentence) then
            past = past + 1
            for _, figure in ipairs(carried_figures(sentence, golden)) do
               if figure.count ~= golden.codes[figure.code] then
                  historical = historical + 1
               end
            end
         end
      end

      assert_true(past > 0,
         DOC .. " has no sentence naming a past run or stating a count in the "
         .. "past tense. The historical/live distinction is decided by that "
         .. "grammar, so a document with none of it cannot be checked")
      assert_true(historical > 0,
         DOC .. " has no historical figure that differs from " .. GOLDEN ..
         ". A document whose prose figures all agree with the measurement is a "
         .. "document that has had its history deleted rather than its stale "
         .. "claims fixed; historical figures disagree with the measurement by "
         .. "definition, and they are what a reader needs to see")
   end)

   it("says which of its numbers are authoritative", function()
      -- The gate above catches a stale sentence. It cannot catch a future one
      -- written so the grammar does not see it, and no prose gate can: that is
      -- the argument for the rule the document now states rather than the lint
      -- the alternative was. So the document has to say, in its own words, that
      -- the table is where a current count lives - and a reader changing a rule
      -- has to be able to find that from the file rather than infer it.
      --
      -- This is the acceptance that cannot be automated: a document that does
      -- not say which copy is authoritative leaves every future contributor
      -- guessing, and guessing is how five stale figures reached one review.
      local text = read_precision_doc()

      assert_true(text:find("the only place", 1, true) ~= nil,
         DOC .. " does not say that the per-code table is the only place a current "
         .. "per-code count appears")
      assert_true(text:find(GOLDEN, 1, true) ~= nil,
         DOC .. " does not name " .. GOLDEN .. ", so a contributor changing a count "
         .. "is not told which file to update")
      assert_true(text:find("#258", 1, true) ~= nil,
         DOC .. " does not point at the issue this rule came from, so the rule "
         .. "reads as housekeeping rather than as a response to a real drift")
   end)
end)