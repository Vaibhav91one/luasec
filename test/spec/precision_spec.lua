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

   it("names the corpus size the headline was measured over", function()
      local text = read_precision_doc()
      local corpus_files = assert(tonumber(text:match("| %*%*total%*%* | %*%*(%d+)%*%*")),
         "the corpora table has no total")
      local headline_files = assert(tonumber(text:match("(%d+) files")),
         "the headline does not say how many files it measured")

      assert_equal(corpus_files, headline_files,
         "the corpus table counts " .. corpus_files ..
         " files and the headline claims " .. headline_files)
   end)

   it("gives the command that reproduces the number", function()
      -- A measurement nobody can re-run is an assertion. The command is the
      -- difference between the two, so its absence is a failure.
      local text = read_precision_doc()
      assert_true(text:find("bin/luasec", 1, true) ~= nil,
         "the document does not say how to reproduce the measurement")
   end)
end)
