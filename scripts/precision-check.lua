-- Compare a fresh corpus run against the frozen measurement and the document.
--
-- usage: make precision   (which runs this)
--        lua scripts/precision-check.lua --report <report.json> --corpus <dir>
--
-- Three copies of one measurement are held against each other here:
--
--   the run       what lua-doctor just found over corpus/
--   the golden     scripts/precision-golden.lua, the frozen copy
--   the document   docs/precision.md, the prose copy
--
-- The document is the project's central claim about itself and it has been wrong
-- three times. Every time the headline was edited by hand, the table below it was
-- not, and the spec that checks the two against each other passed anyway,
-- because a rule that changes what the tool finds moves both at once. This runs
-- the analyzer, so it is the half of the gate that can notice the third kind of
-- mistake: a rule regression, where the document is internally consistent and
-- describes a run that no longer happens.
--
-- Exits 0 when all three agree, 1 when they differ, and 2 when the comparison
-- could not be run at all. A missing corpus, an unreadable report and a corpus
-- with no Lua in it are all 2 or a named failure, never a pass: a gate that
-- cannot run must not come out green.
--
-- The report is read with lua-doctor's own reader and the file count with lua-doctor's
-- own walk, because both are the tool's definitions of its own output. Reading
-- the JSON with a parser written here instead would be a second definition of
-- what a finding is, and the two would disagree one day without anyone noticing
-- which one the analyzer honours.

local function usage(message)
   if message then io.stderr:write("precision-check: " .. message .. "\n") end
   io.stderr:write(
      "usage: precision-check.lua --report <report.json> --corpus <dir>" ..
      " [--golden <file>] [--doc <file>]\n")
   os.exit(2)
end

-- ---------------------------------------------------------------- arguments

local opts = {golden = "scripts/precision-golden.lua", doc = "docs/precision.md"}
local index = 1
while index <= #arg do
   local flag, value = arg[index], arg[index + 1]
   if flag == "--report" and value then
      opts.report, index = value, index + 2
   elseif flag == "--corpus" and value then
      opts.corpus, index = value, index + 2
   elseif flag == "--golden" and value then
      opts.golden, index = value, index + 2
   elseif flag == "--doc" and value then
      opts.doc, index = value, index + 2
   else
      usage("unexpected argument: " .. tostring(flag))
   end
end

if not opts.report or not opts.corpus then
   usage("--report and --corpus are both required: without the corpus this is not a measurement")
end

-- ---------------------------------------------------------------- the golden

local function read_file(path)
   local handle = io.open(path, "r")
   if not handle then return nil, "cannot read " .. path end
   local text = handle:read("*a")
   handle:close()
   return text
end

local function load_golden(path)
   local chunk, load_error = loadfile(path)
   if not chunk then return nil, "cannot load " .. path .. ": " .. tostring(load_error) end
   local ok, value = pcall(chunk)
   if not ok or type(value) ~= "table" or type(value.codes) ~= "table" then
      return nil, path .. " did not return a measurement table"
   end
   for _, field in ipairs({"total", "corpus_files", "scanned_files"}) do
      if type(value[field]) ~= "number" then
         return nil, path .. " has no numeric `" .. field .. "`"
      end
   end
   return value
end

local golden, golden_error = load_golden(opts.golden)
if not golden then usage(golden_error) end

-- ---------------------------------------------------------------- the report

local report_text, report_read_error = read_file(opts.report)
if not report_text then usage(report_read_error) end

local findings_module = require "luasec.report.findings"
local document, document_error = findings_module.read_document(report_text)
if not document then usage(opts.report .. ": " .. tostring(document_error)) end

local measured = {}
local total = 0
for _, finding in ipairs(document.findings) do
   local code = tostring(finding.id)
   measured[code] = (measured[code] or 0) + 1
   total = total + 1
end

-- ---------------------------------------------------------------- the corpus

-- The two file counts, which are not the same number and are both frozen.
--
--   collected  the .lua files under the tree: the denominator docs/precision.md
--              quotes, and what `make corpus` prints per corpus.
--   scanned    the files lua-doctor itself selected, asked of lua-doctor. The walk reads
--              cgi-bin handlers and the extensionless scripts beside them, and
--              declines a few *.lua files on their name, so this is the analyzer's
--              real denominator and not the document's.
--
-- Counting the first one here rather than trusting the document is the point: if
-- the corpora drift, the document's denominator stops being true and that has to
-- be a failure, not a sentence nobody re-reads.
local function collected_lua_files(root)
   local pipe = io.popen(string.format(
      "find -L %s -name '*.lua' -type f 2>/dev/null | wc -l", string.format("%q", root)))
   if not pipe then return nil, "could not count .lua files under " .. root end
   local answer = pipe:read("*l")
   pipe:close()
   return tonumber((answer or ""):match("%d+"))
end

local walk = require "luasec.cli.walk"
local files, walk_error = walk.collect({opts.corpus})
if not files then usage("could not walk " .. opts.corpus .. ": " .. tostring(walk_error)) end

local collected, collected_error = collected_lua_files(opts.corpus)
if not collected then usage(collected_error) end

-- ---------------------------------------------------------------- the report

io.write(string.format("precision: measured %d findings over %d scanned files (%d .lua files) in %s\n",
   total, #files, collected, opts.corpus))

local codes = {}
for code in pairs(measured) do codes[#codes + 1] = code end
table.sort(codes, function(a, b) return tonumber(a) < tonumber(b) end)

local golden_codes = {}
for code in pairs(golden.codes) do golden_codes[#golden_codes + 1] = code end
table.sort(golden_codes, function(a, b) return a < b end)

for _, code in ipairs(codes) do
   io.write(string.format("  %-4s run %-4d golden %s\n", code, measured[code],
      tostring(golden.codes[tonumber(code)] or "ABSENT")))
end
for _, code in ipairs(golden_codes) do
   if not measured[tostring(code)] then
      io.write(string.format("  %-4s run %-4d golden %d\n", code, 0, golden.codes[code]))
   end
end

-- ---------------------------------------------------------------- the document

-- The per-code table, bounded to the table: the scan stops at the first line that
-- is not a row, so a later table in the document cannot be swept in.
--
-- This parse is deliberately not shared with test/spec/precision_golden_spec.lua.
-- The two run in different conditions - that one with no corpus and no src/ on
-- the path at all - and each has to be able to fail on its own. The parse is
-- cross-checked instead: precision_spec.lua reads the same table with a different
-- pattern and asserts the sum against the headline, so a parser that misreads a
-- row fails there rather than agreeing with this one here.
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

local doc_text, doc_read_error = read_file(opts.doc)
if not doc_text then usage(doc_read_error) end

local ok_rows, rows_or_error = pcall(doc_rows, doc_text)
if not ok_rows then usage(opts.doc .. ": " .. tostring(rows_or_error)) end
local rows = rows_or_error

if #rows == 0 then usage(opts.doc .. ": the per-code table is empty") end

-- ---------------------------------------------------------------- differences

local differences = {}

local function difference(message)
   differences[#differences + 1] = message
end

-- The run against the golden, both directions: a code the tool found that the
-- measurement does not record is a rule that changed without a re-measurement,
-- and a count that moved is a document that has not been told yet.
for _, code in ipairs(codes) do
   local recorded = golden.codes[tonumber(code)]
   if recorded == nil then
      difference(string.format("code %s: this run found %d and the frozen measurement in %s has no such code",
         code, measured[code], opts.golden))
   elseif recorded ~= measured[code] then
      difference(string.format("code %s: this run found %d, the frozen measurement says %d",
         code, measured[code], recorded))
   end
end
for _, code in ipairs(golden_codes) do
   if not measured[tostring(code)] and golden.codes[code] ~= 0 then
      difference(string.format("code %d: the frozen measurement says %d and this run found none",
         code, golden.codes[code]))
   end
end

if total ~= golden.total then
   difference(string.format("total: this run found %d, the frozen measurement says %d",
      total, golden.total))
end

if #files ~= golden.scanned_files then
   difference(string.format("scanned files: lua-doctor analyzed %d, the frozen measurement says %d",
      #files, golden.scanned_files))
end

if collected ~= golden.corpus_files then
   difference(string.format("corpus files: %s holds %d .lua files, the frozen measurement says %d",
      opts.corpus, collected, golden.corpus_files))
end

-- The golden against the document, both directions, so a run that matches the
-- golden and a document that matches nothing still cannot both be true.
local function doc_row(code)
   for _, row in ipairs(rows) do
      if row.code == code then return row end
   end
   return nil
end

for _, code in ipairs(golden_codes) do
   local row = doc_row(string.format("%d", code))
   if not row then
      difference(string.format("code %d: the frozen measurement records %d and %s does not mention it",
         code, golden.codes[code], opts.doc))
   elseif row.count ~= golden.codes[code] then
      difference(string.format("code %d: the frozen measurement says %d, %s says %d",
         code, golden.codes[code], opts.doc, row.count))
   end
end
for _, row in ipairs(rows) do
   local recorded = golden.codes[tonumber(row.code)]
   if recorded == nil then
      difference(string.format("code %s (%s): %s claims %d and the frozen measurement has no such code",
         row.code, row.label, opts.doc, row.count))
   elseif recorded ~= row.count then
      difference(string.format("code %s: %s says %d, the frozen measurement says %d",
         row.code, opts.doc, row.count, recorded))
   end
end

-- The document's own headline, which is the sentence a reader quotes first.
local headline = tonumber(doc_text:match("(%d+) findings over"))
local headline_files = tonumber(doc_text:match("(%d+) files"))
if headline == nil then
   difference(opts.doc .. ": the headline finding count is missing")
elseif headline ~= golden.total then
   difference(string.format("headline: %s claims %d findings, the frozen measurement says %d",
      opts.doc, headline, golden.total))
end
if headline_files == nil then
   difference(opts.doc .. ": the headline does not say how many files it measured")
-- The headline carries the ANALYZED count, not the collected one: the findings
-- were divided by the files lua-doctor looked at, so that is the denominator a
-- reader quoting the headline is quoting. The corpus table's own figure is
-- checked against corpus_files below.
elseif headline_files ~= golden.scanned_files then
   difference(string.format("headline: %s claims %d files, the frozen measurement analyzed %d",
      opts.doc, headline_files, golden.scanned_files))
end

local doc_total = tonumber(doc_text:match("%*%*total%*%*%s*|%s*%*%*(%d+)%*%*"))
if doc_total == nil then
   difference(opts.doc .. ": the corpora table has no total")
elseif doc_total ~= golden.corpus_files then
   difference(string.format("corpora table: %s claims %d files, the frozen measurement collected %d",
      opts.doc, doc_total, golden.corpus_files))
end

-- ---------------------------------------------------------------- verdict

if #differences == 0 then
   io.write(string.format("precision: ok (%d findings over %d scanned files, %d .lua files, unchanged)\n",
      total, #files, collected))
   os.exit(0)
end

for _, message in ipairs(differences) do
   io.write("precision: FAILED - ", message, "\n")
end
io.write(string.format("precision: FAILED - %d difference%s; the measurement moved or a copy of it is stale\n",
   #differences, #differences == 1 and "" or "s"))
io.write("precision: re-measure with `make corpus && make precision`, then update ",
   opts.golden, " and ", opts.doc, " in the same commit\n")
os.exit(1)
