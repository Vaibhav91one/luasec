local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

-- The successor to precision_spec.lua, and the half of the precision gate that
-- runs everywhere.
--
-- That spec checks docs/precision.md against itself: the per-code table has to
-- sum to the headline printed above it. It passed through all three times the
-- document was wrong, and it would pass through the fourth, because a rule
-- regression moves the table and the headline together. The document agreed with
-- itself at 150 findings over a corpus that now measures 249, and `make
-- ci-verify` was green throughout: nothing in the gate ran the analyzer.
--
-- So the numbers are frozen outside the document, in scripts/precision-golden.lua,
-- and this spec holds the document to them in both directions. A code that
-- reaches the tool without a measurement and a measurement that is edited without
-- the tool are the same failure, and both of them are this spec failing.
--
-- The other half is `make precision`, which re-takes the measurement and holds
-- the same three numbers against a real run. This one needs no corpus and no
-- network, so the document cannot drift while the corpora are absent - which is
-- the state of a fresh checkout, and therefore the state of every CI run.
--
-- One check of each kind between the two specs, not two. This does not re-assert
-- that the table sums to the headline: with the table pinned to the golden, and
-- the golden's own codes summing to the golden's own total, that already holds,
-- and saying it twice would only add a third place for the copies to disagree.

local GOLDEN = "scripts/precision-golden.lua"
local DOC = "docs/precision.md"

local function read_file(path)
   local handle = assert(io.open(path, "r"), "cannot read " .. path)
   local text = handle:read("*a")
   handle:close()
   return text
end

-- The golden file is data, and `dofile` is the whole of the parser. A file that
-- does not load, or that loads into the wrong shape, is a failure here rather
-- than an empty table that every comparison below then passes on.
local function golden()
   local chunk = assert(loadfile(GOLDEN), GOLDEN .. " does not load")
   local frozen = chunk()
   assert_true(type(frozen) == "table", GOLDEN .. " must return a table")
   assert_true(type(frozen.codes) == "table", GOLDEN .. " must return a `codes` table")
   for _, field in ipairs({"total", "corpus_files", "scanned_files"}) do
      assert_true(type(frozen[field]) == "number",
         GOLDEN .. " has no numeric `" .. field .. "`")
   end
   return frozen
end

-- The document's per-code table, as {code = "724", label = "RPC handler", count = 27}.
--
-- Bounded to the table itself: the scan stops at the first line that is not a
-- table row, so a second table added to the document later cannot be swept into
-- this one and start failing the comparison for the wrong reason.
local function doc_rows(text)
   local header = assert(text:find("| Code | Count | Assessment |", 1, true),
      "the per-code table is gone")
   local rows = {}
   for line in text:sub(header):gmatch("[^\n]+") do
      if not line:match("^%s*|") then break end
      local code, label, count = line:match("^%s*|%s*(%d%d%d)([^|]*)|%s*(%d+)%s*|")
      if code then
         rows[#rows + 1] = {code = code, label = label:gsub("^%s*(.-)%s*$", "%1"),
                            count = tonumber(count)}
      end
   end
   return rows
end

local function doc_row_for(rows, code)
   for _, row in ipairs(rows) do
      if row.code == code then return row end
   end
   return nil
end

describe("the frozen precision measurement", function()
   it("is a breakdown that adds up to its own total", function()
      local frozen = golden()

      -- The document is checked against this sum by way of the per-code
      -- comparison below, which is stricter than a sum: it says which code moved.
      -- This case is the one that keeps the golden file itself honest.
      local total, measured = 0, 0
      for code, count in pairs(frozen.codes) do
         assert_true(type(code) == "number" and code >= 100 and code <= 999,
            GOLDEN .. " has a code that is not a three digit rule code: " .. tostring(code))
         assert_true(type(count) == "number" and count >= 0 and count % 1 == 0,
            GOLDEN .. " code " .. code .. " has a count that is not a whole number of findings: "
               .. tostring(count))
         total = total + count
         measured = measured + 1
      end

      -- The exact number of codes moves whenever a rule is added or dropped; that
      -- it is a list of this size does not. An emptied file must not be a way to
      -- make the document comparison pass.
      assert_true(measured >= 10, GOLDEN .. " lists only " .. measured ..
         " codes; a measurement of this corpus lists the codes it reported")

      assert_equal(total, frozen.total,
         GOLDEN .. " codes sum to " .. total .. " but it declares a total of " ..
         frozen.total .. "; one of them is stale")
   end)

   it("names every count the document claims", function()
      -- Document -> golden. The direction that catches a measurement edited
      -- without the tool: a count nobody re-measured, or a code the document
      -- claims that the frozen run never reported.
      local frozen = golden()
      local rows = doc_rows(read_file(DOC))
      assert_true(#rows > 0, "the per-code table is empty")

      for _, row in ipairs(rows) do
         local recorded = frozen.codes[tonumber(row.code)]
         assert_true(recorded ~= nil,
            DOC .. " claims code " .. row.code .. " (" .. row.label .. ") found " ..
            row.count .. " times on this corpus, and " .. GOLDEN ..
            " has no measurement of it. A code that reaches the document without a" ..
            " run behind it is the failure this gate exists for; re-measure with" ..
            " `make corpus && make precision` and record the count")

         assert_equal(recorded, row.count,
            "code " .. row.code .. ": " .. DOC .. " says " .. row.count ..
            " and the frozen measurement says " .. recorded)
      end
   end)

   it("is named by every count the document could have edited", function()
      -- Golden -> document. The direction that catches a code added to the tool
      -- without a measurement, and the reason this is not just the sum: a code
      -- missing from the document does not change the total, so a table that
      -- still adds up to the headline passes the old spec with a rule missing
      -- from it. 747 is the live case - a measured zero, and a row the document
      -- has to keep.
      local frozen = golden()
      local rows = doc_rows(read_file(DOC))

      for code, count in pairs(frozen.codes) do
         local key = string.format("%d", code)
         local row = doc_row_for(rows, key)
         assert_true(row ~= nil,
            "the frozen measurement records code " .. key .. " finding " .. count ..
            " time" .. (count == 1 and "" or "s") .. " on this corpus, and " .. DOC ..
            " does not mention it in its per-code table. Either the rule changed" ..
            " without the document, or the document was edited without a run")

         assert_equal(row.count, count,
            "code " .. key .. ": the frozen measurement says " .. count ..
            " and " .. DOC .. " says " .. row.count)
      end
   end)

   it("is the number the document's headline quotes", function()
      -- The old spec compares the headline to the table above it. This compares
      -- both to the frozen measurement, which is the copy that does not move
      -- when a rule does.
      local frozen = golden()
      local text = read_file(DOC)

      local headline = assert(tonumber(text:match("(%d+) findings over")),
         "the headline finding count is missing")
      local files = assert(tonumber(text:match("(%d+) files")),
         "the headline does not say how many files it measured")

      assert_equal(headline, frozen.total,
         "the headline claims " .. headline .. " findings and the frozen measurement is " ..
         frozen.total .. "; re-measure with `make corpus && make precision` and update " ..
         GOLDEN .. " and " .. DOC .. " together")

      -- The headline carries the ANALYZED count, not the collected one: 146
      -- findings were divided by the files lua-doctor looked at. The document says
      -- so in words, and precision_spec checks the other half of the pair.
      assert_equal(files, frozen.scanned_files,
         "the headline claims " .. files .. " files and the frozen measurement "
         .. "analyzed " .. frozen.scanned_files .. ". The corpus table's "
         .. frozen.corpus_files .. " is what `make corpus` collects, which is a "
         .. "different question")
   end)
end)
