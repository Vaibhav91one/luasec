local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luasec.api"

-- The codes a report carries, sorted and joined, for exact-match assertions.
local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

-- Every finding carrying one code, in report order.
local function with_code(report, code)
   local out = {}
   for _, finding in ipairs(report) do
      if finding.code == code then out[#out + 1] = finding end
   end
   return out
end

local function fixture(name)
   return api.analyze({"test/fixtures/payload/" .. name .. ".lua"})
end

-- The trace of a finding, joined the way the specs above read it.
local function trace_names(finding)
   local names = {}
   for _, step in ipairs(finding.trace) do names[#names + 1] = step.name end
   return table.concat(names, " -> ")
end

-- 741 reads a function's body and calls a `gsub` with a function replacement a
-- decoder. Every decoder is written that way and so is every text rewrite:
-- `luasec`'s own #256 already ruled that a function which only rewrites the
-- string it is holding is not a decode (`luadoc`'s `translate`, silenced
-- because it substitutes with a string). A substitution function only closes
-- that gap when the replacement itself is what makes the bytes.
--
-- These two fixtures are the same program with one fact changed, and which of
-- them fires is what issue #266 is decided on.
describe("a substitution function handed to gsub", function()
   -- The negative that decides the change. The decoder here is called `stage`,
   -- so no decoder word in its name can be what reports it: the replacement
   -- function building a character is the whole of the evidence. If this stops
   -- firing, a real detector was deleted rather than a false one corrected.
   it("still reports 741 critical for a blob decoded through a substitution function and loaded", function()
      local report = fixture("substitution_stage")
      local found = with_code(report, "741")
      assert_equal(#found, 1, "a staged loader using gsub with a function is the backdoor shape: "
         .. codes(report))
      assert_equal(found[1].name, "load", "the finding names the loader API")
      assert_equal(found[1].severity, "critical",
         "the chain is read end to end, so this is the worst case rather than a hint")
      assert_equal(found[1].line, 14, "the load is on line 14 of the fixture")
      assert_equal(trace_names(found[1]), "stage -> substitution decode -> load",
         "the trace names the decoder, what it does, and the loader it reached")
   end)

   -- The correction. This is `corpus/luajit/src/host/genlibbc.lua` reduced: a
   -- build tool whose replacement functions are closures that format text and
   -- return formatted text. It compiles the source it is holding in the open -
   -- nothing hidden, nothing fetched, nothing attacker-controlled - which is
   -- what this module already calls script loading rather than a hidden payload.
   it("reports no 741 for a program that compiles the source it is holding", function()
      local report = fixture("source_rewrite")
      assert_equal(#with_code(report, "741"), 0,
         "a build tool rewriting the markers in its own source and compiling the result is not "
            .. "a hidden payload: " .. codes(report))
      assert_true(#with_code(report, "703") >= 1,
         "the loader is still a dynamic-evaluation sink and 703 still speaks about it: " .. codes(report))
   end)

   -- The boundary, stated so a future change cannot move it quietly. These two
   -- programs differ by exactly one line - the replacement function - and by
   -- nothing else: same shape, same call, same neutral decoder name, so neither
   -- is carried by a decoder word. The one that turns a byte into the payload is
   -- a decoder. The one that formats text and rewrites its subject is a rewrite.
   it("separates the two by whether the replacement function builds the payload", function()
      local builds = [[
local function conv(hex)
   return (hex:gsub("%x%x", function(pair) return string.char(tonumber(pair, 16)) end))
end
load(conv("4c4a0202"), "=x")
]]
      local formats = [[
local function conv(src)
   return (src:gsub("MARK%((.-)%)", function(var) return string.format("x=%d", var:byte()) end))
end
load(conv("MARK(1)"), "=x")
]]

      local built = with_code(api.check_source(builds), "741")
      assert_equal(#built, 1,
         "a replacement function that builds the payload is a decoder: " .. codes(api.check_source(builds)))
      assert_equal(trace_names(built[1]), "conv -> substitution decode -> load")

      local formatted = api.check_source(formats)
      assert_equal(#with_code(formatted, "741"), 0,
         "the same program with a replacement that only reformats its subject is a rewrite: "
            .. codes(formatted))
      assert_equal(#with_code(formatted, "901"), 0, "it was judged, not skipped: " .. codes(formatted))
   end)
end)
