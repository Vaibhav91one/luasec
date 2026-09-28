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

local function read_precision_doc()
   local handle = assert(io.open("docs/precision.md", "r"))
   local text = handle:read("*a")
   handle:close()
   return text
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
      local frozen = dofile("scripts/precision-golden.lua")

      assert_equal(headline_files, frozen.scanned_files,
         "the headline claims " .. headline_files .. " files; the frozen measurement "
         .. "analyzed " .. frozen.scanned_files)
      assert_equal(corpus_files, frozen.corpus_files,
         "the corpus table claims " .. corpus_files .. " files; the frozen "
         .. "measurement collected " .. frozen.corpus_files)
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
end)
