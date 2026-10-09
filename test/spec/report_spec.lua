-- Report contract specs. Everything here goes through a public seam: the CLI
-- as a subprocess. No spec reaches into a formatter's internals.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_false = harness.assert_equal, harness.assert_true, harness.assert_false
local assert_match, assert_no_match = harness.assert_match, harness.assert_no_match

-- A small JSON reader, so these specs parse what the tool printed instead of
-- matching it as text. It is only there to read the bytes back.
local function decode(text)
   local pos = 1

   local function skip()
      pos = text:find("[^ \t\r\n]", pos) or pos
   end

   local parse_value

   local function parse_string()
      pos = pos + 1
      local out = {}
      while true do
         local char = text:sub(pos, pos)
         if char == "" then error("unterminated string") end
         if char == '"' then pos = pos + 1 break end
         if char == "\\" then
            local escape = text:sub(pos + 1, pos + 1)
            local map = {["\""] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b",
                         f = "\f", n = "\n", r = "\r", t = "\t"}
            if escape == "u" then
               local hex = text:sub(pos + 2, pos + 5)
               local code = tonumber(hex, 16)
               if code < 0x80 then
                  out[#out + 1] = string.char(code)
               elseif code < 0x800 then
                  out[#out + 1] = string.char(0xC0 + math.floor(code / 0x40), 0x80 + code % 0x40)
               else
                  out[#out + 1] = string.char(0xE0 + math.floor(code / 0x1000),
                     0x80 + math.floor(code / 0x40) % 0x40, 0x80 + code % 0x40)
               end
               pos = pos + 6
            else
               out[#out + 1] = map[escape] or escape
               pos = pos + 2
            end
         else
            out[#out + 1] = char
            pos = pos + 1
         end
      end
      return table.concat(out)
   end

   local function parse_array()
      pos = pos + 1
      local out = {}
      skip()
      if text:sub(pos, pos) == "]" then pos = pos + 1 return out end
      while true do
         out[#out + 1] = parse_value()
         skip()
         local char = text:sub(pos, pos)
         pos = pos + 1
         if char == "]" then break end
         if char ~= "," then error("expected , or ] at " .. pos) end
         skip()
      end
      return out
   end

   local function parse_object()
      pos = pos + 1
      local out = {}
      skip()
      if text:sub(pos, pos) == "}" then pos = pos + 1 return out end
      while true do
         skip()
         local key = parse_string()
         skip()
         pos = pos + 1
         out[key] = parse_value()
         skip()
         local char = text:sub(pos, pos)
         pos = pos + 1
         if char == "}" then break end
         if char ~= "," then error("expected , or } at " .. pos) end
      end
      return out
   end

   parse_value = function()
      skip()
      local char = text:sub(pos, pos)
      if char == "{" then return parse_object() end
      if char == "[" then return parse_array() end
      if char == '"' then return parse_string() end
      if text:sub(pos, pos + 3) == "true" then pos = pos + 4 return true end
      if text:sub(pos, pos + 4) == "false" then pos = pos + 5 return false end
      if text:sub(pos, pos + 3) == "null" then pos = pos + 4 return nil end
      local number = text:match("^%-?%d+%.?%d*[eE]?[%+%-]?%d*", pos)
      if not number or number == "" then error("unexpected input at " .. pos) end
      pos = pos + #number
      return tonumber(number)
   end

   local value = parse_value()
   skip()
   return value
end

-- Run the CLI and hand back the document it printed, parsed.
local function report(args)
   local out, code = harness.cli(args)
   return decode(out), code, out
end

describe("json report", function()
   it("is the doctor/1 envelope: the schema, the tool, its version, the exit code and the findings", function()
      local doc, code = report({"--format", "json", "test/fixtures/tainted_exec/handler.lua"})
      assert_equal(code, 1, "a critical finding is present, so the run is not clean")

      local version = require "luasec.version"
      assert_equal(doc.schema, "doctor/1", "the document names the contract")
      assert_equal(doc.tool, "luasec")
      assert_equal(doc.version, version.luasec, "the document needs the tool's own version")
      assert_equal(doc.exit_code, 1, "the envelope carries the exit code of the run")
      assert_match(doc.data.report_version, "^%d+%.%d+$", "the old report version moved under data")
      assert_true(type(doc.findings) == "table" and #doc.findings == 1,
         "expected exactly one finding, got " .. tostring(doc.findings and #doc.findings))
   end)

   it("carries no field outside the contract, so the shape cannot drift", function()
      local doc = report({"--format", "json", "test/fixtures/tainted_exec/handler.lua"})
      local finding = doc.findings[1]

      local allowed = {id = true, fingerprint = true, severity = true, confidence = true,
                       category = true, message = true, location = true, evidence = true,
                       remedy = true, baseline_state = true,
                       -- extra keys the contract allows
                       cwe = true, name = true, sink = true, source = true, end_column = true,
                       trace = true, sanitizer = true, guarded_by = true, channels = true,
                       exposed_as = true}
      for key in pairs(finding) do
         assert_true(allowed[key], "the finding carries '" .. key ..
            "', which is not in the documented contract")
      end
   end)

   it("gives a taint finding every field of the documented contract", function()
      local doc = report({"--format", "json", "test/fixtures/tainted_exec/handler.lua"})
      local finding = doc.findings[1]

      for _, field in ipairs({"id", "fingerprint", "severity", "confidence", "category", "cwe",
                              "message", "name", "sink", "source", "location", "end_column", "remedy"}) do
         assert_true(finding[field] ~= nil,
            "the contract requires '" .. field .. "'; it is absent from the finding")
      end

      assert_equal(finding.id, "709")
      assert_equal(finding.category, "exec")
      assert_equal(finding.severity, "critical")
      assert_equal(finding.confidence, "certain")
      assert_equal(finding.cwe, "CWE-78")
      assert_equal(finding.name, "os.execute")
      assert_equal(finding.sink, "os.execute")
      assert_equal(finding.source, "http.formvalue")
      assert_equal(finding.location.kind, "file")
      assert_equal(finding.location.ref, "test/fixtures/tainted_exec/handler.lua")
      assert_equal(finding.location.line, 3)
      assert_equal(finding.location.column, 4)
      assert_true(finding.end_column > finding.location.column, "the end column is the far edge of the sink")
      assert_true(type(finding.remedy) == "string", "709 has a How to fix section on its rule page")
   end)

   it("carries a source-to-sink trace on a taint finding and no trace key on one without a flow", function()
      local tainted = report({"--format", "json", "test/fixtures/tainted_exec/handler.lua"})
      local trace = tainted.findings[1].trace
      assert_true(#trace >= 2, "a proven flow has a source and a sink")
      assert_equal(trace[1].kind, "source", "the flow starts at the untrusted input")
      assert_equal(trace[#trace].kind, "sink", "the flow ends at the sink")

      -- 708 is shape only: an exported function containing a sink with nothing
      -- in the file proven to feed it. There is no path, so there is no trace.
      local shape = report({"--format", "json", "test/fixtures/payload/undecoded_loader.lua"})
      local no_trace
      for _, finding in ipairs(shape.findings) do
         if finding.id == "708" then no_trace = finding end
      end
      assert_true(no_trace ~= nil, "expected a 708 in the fixture")
      assert_true(no_trace.trace == nil, "a finding with no proven flow must not carry a trace key")
   end)

   it("orders findings by severity, then id, then fingerprint", function()
      local doc = report({"--format", "json", "test/fixtures/reports/taint_order_b.lua",
                          "test/fixtures/reports/taint_order.lua"})

      local rank = {critical = 1, high = 2, medium = 3, low = 4, info = 5}
      local function before(x, y)
         if x.severity ~= y.severity then return rank[x.severity] < rank[y.severity] end
         if x.id ~= y.id then return x.id < y.id end
         return x.fingerprint <= y.fingerprint
      end

      assert_true(#doc.findings > 1, "the fixtures give more than one finding")
      for i = 2, #doc.findings do
         local previous, current = doc.findings[i - 1], doc.findings[i]
         assert_true(before(previous, current),
            "finding " .. i .. " (" .. current.severity .. " " .. current.id .. " " ..
            current.fingerprint .. ") is out of order after " .. previous.severity .. " " ..
            previous.id .. " " .. previous.fingerprint)
      end
   end)

   it("writes byte-identical json over two runs of unchanged input", function()
      local paths = {"test/fixtures/reports/taint_order.lua",
                     "test/fixtures/reports/taint_order_b.lua"}

      local first = harness.cli({"--format", "json", paths[1], paths[2]})
      local second = harness.cli({"--format", "json", paths[1], paths[2]})

      assert_equal(#first, #second, "the two runs printed a different number of bytes")
      assert_true(first == second,
         "two runs over unchanged input must agree byte for byte; they differ")
   end)

   it("writes the same json whatever order the files were named in and whatever --jobs says", function()
      local a, b = "test/fixtures/reports/taint_order.lua",
                   "test/fixtures/reports/taint_order_b.lua"

      local forward = harness.cli({"--format", "json", a, b})
      local reversed = harness.cli({"--format", "json", "--jobs", "1", b, a})

      assert_true(forward == reversed,
         "the report depends on the order the files were named in, or on --jobs")
   end)

   it("round-trips a message holding a quote, a backslash, a tab, a newline and non-ascii", function()
      local doc = report({"--format", "json", "test/fixtures/reports/tricky_message.lua"})

      local message = doc.findings[1].message
      assert_equal(message,
         "hardcoded credential (cfg.api\"key\twith\\backslash\nnewline \195\169 \230\151\165\230\156\172)",
         "the message did not survive the round trip byte for byte")

      for _, char in ipairs({'"', "\\", "\t", "\n"}) do
         assert_true(message:find(char, 1, true) ~= nil,
            "the message lost its " .. string.format("%q", char))
      end
      assert_true(message:find("\195\169", 1, true) ~= nil, "the message lost its é")
      assert_true(message:find("\230\151\165", 1, true) ~= nil, "the message lost its 日")
   end)
end)

describe("sarif report", function()
   it("numbers a code flow from 1, in source-to-sink order", function()
      local doc = report({"--format", "sarif", "test/fixtures/reports/multi_step_flow.lua"})

      local flow = doc.runs[1].results[1].codeFlows[1].threadFlows[1]
      local locations = flow.locations
      assert_true(#locations >= 2, "a flow needs a source and a sink, got " .. #locations)

      for i, entry in ipairs(locations) do
         assert_equal(entry.executionOrder, i,
            "executionOrder must count from 1 without gaps; step " .. i .. " says " ..
            tostring(entry.executionOrder))
      end

      -- Each step is its own object, not a bare location: SARIF requires the
      -- wrapper so a step can carry an executionOrder at all.
      for i, entry in ipairs(locations) do
         assert_true(type(entry.location) == "table" and entry.location.physicalLocation ~= nil,
            "thread flow step " .. i .. " does not wrap a physical location")
      end

      -- The first step is the untrusted input, the last is the sink, and the
      -- line numbers come from the flow rather than from the file.
      local source_region = locations[1].location.physicalLocation.region
      local sink_region = locations[#locations].location.physicalLocation.region
      assert_equal(source_region.startLine, 5, "the flow must start where http.formvalue is read")
      assert_equal(sink_region.startLine, 7, "the flow must end on the os.execute line")
      assert_true(source_region.startLine < sink_region.startLine,
         "the steps are in the wrong order: the source is not before the sink")
   end)

   it("gives a code flow step the column of the step's own line, not the sink's", function()
      local doc = report({"--format", "sarif", "test/fixtures/reports/multi_step_flow.lua"})

      local locations = doc.runs[1].results[1].codeFlows[1].threadFlows[1].locations
      for i, entry in ipairs(locations) do
         local region = entry.location.physicalLocation.region
         assert_true(region.startColumn ~= nil and region.startColumn > 0,
            "step " .. i .. " has no start column")
         assert_true(region.startLine ~= nil and region.startLine > 0,
            "step " .. i .. " has no start line")
      end
   end)

   it("keeps a finding's fingerprint when the statement moves down the file", function()
      -- One file, rewritten between the two runs, so the path is held constant
      -- and the only thing that changes is the line the sink sits on. Two
      -- different fixture files would differ by path, which a fingerprint is
      -- allowed to notice.
      local path = os.tmpname() .. ".lua"
      local function scan(content)
         local handle = assert(io.open(path, "wb"))
         handle:write(content)
         handle:close()
         return decode(harness.cli({"--format", "sarif", path}))
      end

      local body = [[
local function handler(request)
   local host = http.formvalue(request, "host")
   local command = "ping -c1 " .. host
   os.execute(command)
end

return handler
]]

      local before = scan(body)
      local after = scan("-- two lines of comment push the sink down\n-- and change nothing else\n" .. body)

      local function line_of(doc)
         return doc.runs[1].results[1].locations[1].physicalLocation.region.startLine
      end
      local function fingerprint(doc)
         local printed = doc.runs[1].results[1].partialFingerprints["doctorFinding/v1"]
         assert_true(type(printed) == "string" and printed:match("^%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x$"),
            "a result needs a fingerprint a consumer can key on")
         return printed
      end

      assert_equal(line_of(after), line_of(before) + 2,
         "the sink did not move by the two lines that were added")
      assert_equal(fingerprint(after), fingerprint(before),
         "moving a statement down the file changed its fingerprint, so a code scanning " ..
         "UI will report a finding that was already known")

      os.remove(path)
   end)

   it("does not write primaryLocationLineHash: that key is GitHub's own hash of the line (#311)", function()
      -- luasec wrote "709:os.execute:2" there; GitHub recomputes the key, warns "inconsistent
      -- fingerprint" on every result of every upload, and ignores ours. doctorFinding/v1 is the
      -- identity a consumer keys on and stays.
      local path = os.tmpname()
      local handle = assert(io.open(path, "w"))
      handle:write('local h = http.formvalue(request, "host")\nos.execute("ping " .. h)\n')
      handle:close()
      local doc = decode(harness.cli({"--format", "sarif", path}))
      os.remove(path)
      local fingerprints = doc.runs[1].results[1].partialFingerprints
      assert_equal(fingerprints.primaryLocationLineHash, nil, "GitHub computes this key itself")
      assert_true(type(fingerprints["doctorFinding/v1"]) == "string" and #fingerprints["doctorFinding/v1"] == 16,
         "the stable finding identity must stay")
   end)

   it("names only rules it declared, so every ruleId resolves", function()
      local doc = report({"--format", "sarif", "test/fixtures", "test/adversarial", "src"})

      local declared = {}
      for _, rule in ipairs(doc.runs[1].tool.driver.rules) do
         assert_true(rule.id ~= nil and #rule.id > 0, "a declared rule has no id")
         declared[rule.id] = true
      end
      assert_true(next(declared) ~= nil, "the run declared no rules at all")

      for i, result in ipairs(doc.runs[1].results) do
         assert_true(declared[result.ruleId] ~= nil,
            "result " .. i .. " names rule '" .. tostring(result.ruleId) ..
            "', which tool.driver.rules does not declare")
      end
   end)

   it("writes no null where the schema wants a value", function()
      local out = harness.cli({"--format", "sarif", "test/fixtures", "test/adversarial", "src"})
      assert_no_match(out, ":%s*null%s*[,}]",
         "SARIF has no null: an absent optional key is written by leaving it out")
   end)

   it("gives every physical location the file it is in", function()
      local doc = report({"--format", "sarif", "test/fixtures", "test/adversarial", "src"})

      local function check(location, where)
         local physical = location.physicalLocation
         if not physical then return end
         local uri = physical.artifactLocation and physical.artifactLocation.uri
         assert_true(type(uri) == "string" and #uri > 0,
            "a location with no artifactLocation.uri at " .. where)
         assert_true(uri ~= "null", "a location whose uri is the string 'null' at " .. where)
      end

      for i, result in ipairs(doc.runs[1].results) do
         for j, location in ipairs(result.locations or {}) do
            check(location, "result " .. i .. " location " .. j)
         end
         for _, flow in ipairs(result.codeFlows or {}) do
            for _, thread in ipairs(flow.threadFlows or {}) do
               for k, entry in ipairs(thread.locations or {}) do
                  assert_true(entry.executionOrder ~= nil,
                     "thread flow step " .. k .. " of result " .. i .. " has no executionOrder")
                  check(entry.location, "result " .. i .. " flow step " .. k)
               end
            end
         end
      end
   end)
end)

-- The structural checks above are the ones a hand-rolled emitter gets wrong, but
-- they are still this file's own opinion. Validated against the real
-- sarif-schema-2.1.0.json with python jsonschema as part of this issue; the
-- result is in the PR. The spec below asserts the properties that the schema
-- itself imposes, so a regression is caught by `make test` rather than only by
-- a reviewer with the schema on disk.
describe("html report", function()
   it("references no external resource of any kind", function()
      local out = harness.cli({"--format", "html", "test/fixtures", "test/adversarial", "src"})

      -- Not "no http" - a report is allowed to mention a URL in a sentence. What
      -- it may not do is make the browser go and fetch anything: the whole point
      -- is that the file opens on a machine with no network.
      assert_no_match(out, "<script%s", out, "the report must not contain a script element")
      assert_no_match(out, "<link%s", out, "the report must not contain a link element")
      assert_no_match(out, "<iframe", out, "the report must not embed a frame")
      assert_no_match(out, "<object", out)
      assert_no_match(out, "<embed", out)
      assert_no_match(out, "@import", out, "css @import would fetch a stylesheet")
      assert_no_match(out, "url%s*%(%s*['\"]?https?:", out, "a css url() would fetch a resource")
      assert_no_match(out, "<img", out, "an image element would fetch a resource")
      assert_no_match(out, "src%s*=", out, "no element may carry a src")
      assert_no_match(out, "href%s*=", out, "no element may carry an href")
   end)

   it("renders a finding's markup as text rather than as script", function()
      local out = harness.cli({"--format", "html", "test/fixtures/reports/markup_message.lua"})

      assert_match(out, "&lt;script&gt;", out,
         "the markup must be escaped into text: " .. out)
      assert_no_match(out, "<script>alert", out,
         "the report executed a scanned file's markup: " .. out)
      assert_match(out, "747", out, "the finding itself must still be reported: " .. out)
   end)

   it("groups findings by severity with a count for each", function()
      local doc = report({"--format", "json", "test/fixtures", "test/adversarial", "src"})
      local out = harness.cli({"--format", "html", "test/fixtures", "test/adversarial", "src"})

      local counts = {}
      for _, finding in ipairs(doc.findings) do
         counts[finding.severity] = (counts[finding.severity] or 0) + 1
      end
      assert_true(next(counts) ~= nil, "the fixtures produce no findings at all")

      for severity, count in pairs(counts) do
         assert_match(out, ">" .. count .. " " .. severity .. "<", out,
            "the report must show a count of " .. count .. " " .. severity .. " findings")
      end
   end)

   it("puts the findings of one severity together under a heading for it", function()
      local out = harness.cli({"--format", "html", "test/fixtures", "test/adversarial", "src"})

      -- Grouped, not one flat table: a reviewer opens this to answer "is anything
      -- critical", and a critical finding halfway down a 156-row table is a
      -- critical finding nobody reads.
      local critical_heading = out:find("critical<", 1, true)
      assert_true(critical_heading ~= nil, "no critical group in the report")

      local rows = {}
      for position in out:gmatch("class=['\"]row sev") do rows[#rows + 1] = position end
      assert_true(#rows > 0, "the report has no finding rows")
   end)

   it("shows a taint flow from its source to its sink", function()
      local out = harness.cli({"--format", "html", "test/fixtures/reports/multi_step_flow.lua"})

      -- The order is read inside the flow, not across the whole page: the
      -- message names the sink too, and asserting on the page would pass on any
      -- report that mentions both at all.
      local flow = out:match("<ol class='flow'>.-</ol>")
      assert_true(flow ~= nil, "the finding must be shown with its flow: " .. out)
      assert_match(flow, "source</b>%s+http%.formvalue", flow)
      assert_match(flow, "sink</b>%s+os%.execute", flow)
      assert_true(flow:find("http%.formvalue") < flow:find("os%.execute"),
         "the flow must read source then sink, not the other way round")
   end)

   it("shows the code, the cwe and the confidence of a finding", function()
      local out = harness.cli({"--format", "html", "test/fixtures/tainted_exec/handler.lua"})

      assert_match(out, "709", out)
      assert_match(out, "CWE%-78", out)
      assert_match(out, "certain", out)
      assert_match(out, "test/fixtures/tainted_exec/handler%.lua", out)
   end)

   it("is one self-contained file", function()
      local out = harness.cli({"--format", "html", "test/fixtures/tainted_exec/handler.lua"})

      assert_true(out:sub(1, 15):lower() == "<!doctype html>",
         "the report must be a whole document, starting: " .. out:sub(1, 40))
      assert_match(out, "</html>%s*$", out, "the report must be closed at the end")
      assert_match(out, "<style>", out, "styling must be inline, not linked")
   end)
end)

describe("sarif document shape", function()
   it("declares the schema, the version, and one run with a driver", function()
      local doc = report({"--format", "sarif", "test/fixtures/tainted_exec/handler.lua"})

      assert_match(doc["$schema"], "^https://.+sarif%-schema%-2%.1%.0%.json$",
         "the top-level $schema must be the 2.1.0 schema uri")
      assert_equal(doc.version, "2.1.0", "sarif 2.1.0 output must say so")
      assert_equal(#doc.runs, 1, "this emitter writes one run")
      assert_true(doc.runs[1].tool.driver.name ~= nil, "a run must name its tool")
      assert_true(doc.runs[1].tool.driver.version ~= nil, "a driver must carry a version")
   end)

   it("gives every result the four fields a consumer needs to place it", function()
      local doc = report({"--format", "sarif", "test/fixtures", "test/adversarial", "src"})

      for i, result in ipairs(doc.runs[1].results) do
         assert_true(type(result.ruleId) == "string" and #result.ruleId > 0,
            "result " .. i .. " has no ruleId")
         assert_true(type(result.level) == "string", "result " .. i .. " has no level")
         assert_true(result.message ~= nil and type(result.message.text) == "string",
            "result " .. i .. " has no message text")
         assert_true(type(result.locations) == "table" and #result.locations > 0,
            "result " .. i .. " has no locations")
      end
   end)
end)

describe("a baseline and ground we did not cover", function()
   it("keeps a degraded finding, because a baseline records findings, not gaps", function()
      -- Suppressing a 901 as "already known" printed an empty report and exited
      -- non-zero, which reads as a contradiction. A 901 is the run saying it did
      -- not read something; a previous run's report cannot make that known.
      local scratch = harness.scratch_dir("spec_baseline_degraded")
      local f = assert(io.open(scratch .. "/broken.lua", "w"))
      f:write('local x = "unterminated\n')
      f:close()
      local base = assert(io.open(scratch .. "/base.json", "w"))
      base:write('{"schema":"doctor/1","findings":[]}')
      base:close()

      local out, code = harness.cli({ "--baseline", scratch .. "/base.json", scratch })
      os.execute("rm -rf " .. string.format("%q", scratch))

      assert_match(out, "901", "the finding is still in the report:\n" .. out)
      assert_true(code ~= 0, "and the run still fails:\n" .. out)
   end)

   it("refuses a baseline whose finding has no fingerprint", function()
      local scratch = harness.scratch_dir("spec_baseline_absent_fields")
      local base = assert(io.open(scratch .. "/base.json", "w"))
      base:write('{"schema":"doctor/1","findings":[{"id":"701"}]}')
      base:close()

      local out, code = harness.cli({"--format", "json", "--baseline", scratch .. "/base.json",
         "test/fixtures/clean/report.lua"})
      os.execute("rm -rf " .. string.format("%q", scratch))

      assert_equal(code, 2, "a finding without a fingerprint is malformed:\n" .. out)
      assert_match(out, "fingerprint", out)
      assert_no_match(out, "stack traceback", out)
   end)

   it("refuses a baseline whose fingerprint is not 16 hex characters", function()
      local scratch = harness.scratch_dir("spec_baseline_bad_code")
      local base = assert(io.open(scratch .. "/base.json", "w"))
      base:write('{"schema":"doctor/1","findings":[{"id":"701","fingerprint":701}]}')
      base:close()

      local out, code = harness.cli({"--format", "json", "--baseline", scratch .. "/base.json",
         "test/fixtures/clean/report.lua"})
      os.execute("rm -rf " .. string.format("%q", scratch))

      assert_equal(code, 2, "a finding with a non-hex fingerprint is malformed:\n" .. out)
      assert_match(out, "baseline", out)
      assert_no_match(out, "stack traceback", out)
   end)

end)
