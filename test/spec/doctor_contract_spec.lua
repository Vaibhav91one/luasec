-- The doctor/1 machine-output contract (docs/doctor-contract.md): the conformance
-- test of section 9, the sanitization test of section 8, and the CLI surface the
-- contract names (--json, --sarif, --fail-on info, MCP).
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true
local assert_match, assert_no_match = harness.assert_match, harness.assert_no_match

local api = require "luasec.api"
local findings = require "luasec.report.findings"

local FIXTURE = "test/fixtures/tainted_exec/handler.lua"

local SEVERITY = {critical = true, high = true, medium = true, low = true, info = true}
local CONFIDENCE = {certain = true, high = true, medium = true, low = true}
local KIND = {file = true, flow = true, frame = true, image = true, ["card-path"] = true,
              device = true, service = true, none = true}

local function run(args)
   local out, code = harness.cli(args)
   return findings.decode(out), code, out
end

describe("the doctor/1 envelope", function()
   it("conforms: keys, enums, exit code, fingerprints, determinism", function()
      local doc, code, out = run({"--json", FIXTURE})
      assert_equal(code, 1)
      assert_equal(doc.schema, "doctor/1")
      assert_equal(doc.tool, "lua-doctor")
      assert_true(type(doc.version) == "string" and doc.version:match("^%d+%.%d+%.%d+$"), "semver")
      assert_equal(doc.exit_code, code, "exit_code is the real exit code")
      assert_equal(doc.score.model, "lua-doctor/1")
      assert_true(type(doc.score.value) == "number" and doc.score.value >= 0 and doc.score.value <= 100)
      assert_true(({good = 1, ["needs work"] = 1, critical = 1, incomplete = 1})[doc.score.label])
      assert_equal(doc.score.coverage_gaps, 0)
      assert_true(type(doc.data) == "table")
      assert_true(#doc.findings > 0)
      for _, finding in ipairs(doc.findings) do
         assert_true(type(finding.id) == "string")
         assert_true(finding.fingerprint:match("^%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x$")
            and finding.fingerprint == finding.fingerprint:lower(), "16 lowercase hex")
         assert_true(SEVERITY[finding.severity], "severity")
         assert_true(finding.confidence == nil or CONFIDENCE[finding.confidence], "confidence")
         assert_true(type(finding.category) == "string" and finding.category ~= "")
         assert_true(type(finding.message) == "string")
         assert_true(KIND[finding.location.kind] and type(finding.location.ref) == "string")
         assert_true(finding.remedy == nil or type(finding.remedy) == "string")
      end
      -- `"remedy": null` decodes to nil, so the key must be present in the text.
      assert_match(out, '"remedy": ', "remedy is always written")

      local again = harness.cli({"--json", FIXTURE})
      assert_equal(again, out, "two runs over the same input give the same bytes")
   end)

   it("writes remedy null when a rule page has no How to fix section", function()
      local text = api.format({{code = "999", severity = "low", confidence = "high", message = "m",
         name = "n", file = "x.lua", line = 1, column = 1}}, "json")
      assert_match(text, '"remedy": null')
   end)

   it("puts the hash of code, name and file in the SARIF partial fingerprint", function()
      local doc = run({"--json", FIXTURE})
      local sarif_path = os.tmpname()
      local _, code = harness.cli({"--sarif", sarif_path, FIXTURE})
      assert_equal(code, 1, "--sarif is a second output; the exit code is unchanged")
      local handle = assert(io.open(sarif_path, "rb"))
      local sarif = findings.decode(handle:read("*a"))
      handle:close()
      os.remove(sarif_path)
      local result = sarif.runs[1].results[1]
      assert_equal(result.partialFingerprints["doctorFinding/v1"], doc.findings[1].fingerprint)
      assert_equal(sarif.runs[1].properties.score.model, "lua-doctor/1")
   end)

   it("accepts --fail-on info and rejects a word that is not a severity", function()
      local _, code = harness.cli({"--fail-on", "info", FIXTURE})
      assert_equal(code, 1)
      local _, bad = harness.cli({"--fail-on", "fatal", FIXTURE})
      assert_equal(bad, 2)
   end)

   it("exits 3 under --baseline for a new finding and lists baseline_state", function()
      local base = os.tmpname()
      local _, written = harness.cli({"--json", "-o", base, "test/fixtures/clean/report.lua"})
      assert_equal(written, 0)
      local doc, code = run({"--json", "--baseline", base, FIXTURE})
      os.remove(base)
      assert_equal(code, 3)
      assert_equal(doc.exit_code, 3)
      assert_equal(doc.baseline.new, 1)
      assert_equal(doc.findings[1].baseline_state, "new")
   end)
end)

describe("sanitization (doctor/1 section 8)", function()
   local HOSTILE = "red\27[31m \226\128\174evil\226\128\139 \194\155 bell\7"

   it("keeps terminal controls and invisible characters out of the plain report", function()
      local out = api.format({{code = "709", severity = "high", confidence = "high", name = "n",
         message = HOSTILE, snippet = HOSTILE, source = HOSTILE, file = "x.lua", line = 1, column = 1}}, "plain")
      assert_no_match(out, "\27", "ESC reached the output")
      assert_no_match(out, "\226\128\174", "a bidi override reached the output")
      assert_no_match(out, "\226\128\139", "a zero-width space reached the output")
      assert_no_match(out, "\194\155", "a C1 control reached the output")
      assert_no_match(out, "\7", "BEL reached the output")
      assert_match(out, "\\x1b", "the escape stays visible, as text")
   end)

   it("keeps them out of the validator report too", function()
      local validate_report = require "luasec.validate.report"
      local out = validate_report.render({verdict = "rce", exit_reason = "x", reason_source = "payload",
         sinks_reached = {}, payload_result = HOSTILE, payload_output = HOSTILE}, "p.lua")
      assert_no_match(out, "\27")
      assert_no_match(out, "\226\128\174")
   end)

   it("leaves JSON to the serializer, which keeps the value and escapes it", function()
      local out = api.format({{code = "709", severity = "high", confidence = "high", name = "n",
         message = HOSTILE, file = "x.lua", line = 1, column = 1}}, "json")
      assert_no_match(out, "\27")
      assert_match(out, "\\u001b")
   end)
end)

describe("lua-doctor mcp", function()
   it("serves scan over stdio and returns the CLI's envelope unchanged", function()
      local requests = table.concat({
         '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}',
         '{"jsonrpc":"2.0","method":"notifications/initialized"}',
         '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
         '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan","arguments":{"path":"'
            .. FIXTURE .. '","fail_on":"high"}}}',
         '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"scan","arguments":{"path":"nope.lua"}}}',
         '{"jsonrpc":"2.0","id":5,"method":"nope"}',
      }, "\n") .. "\n"
      local out, code = harness.cli({"mcp"}, {stdin = requests})
      assert_equal(code, 0)
      local replies = {}
      for line in out:gmatch("[^\n]+") do
         local reply = findings.decode(line)
         replies[reply.id] = reply
      end
      assert_equal(replies[1].result.serverInfo.name, "lua-doctor")
      assert_equal(replies[2].result.tools[1].name, "scan")
      assert_equal(replies[3].result.isError, false)
      local expected = harness.cli({"--json", "--fail-on=high", FIXTURE})
      assert_equal(replies[3].result.content[1].text, (expected:gsub("%s+$", "")) .. "\n",
         "the envelope is the CLI's stdout, byte for byte")
      assert_equal(replies[4].result.isError, true, "exit 2 is a tool error, not an envelope")
      assert_equal(replies[5].error.code, -32601)
      assert_equal(replies[2 + 4], nil, "a notification gets no reply")
   end)
end)
