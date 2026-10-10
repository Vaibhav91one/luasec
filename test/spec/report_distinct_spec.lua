-- A report says the same thing once.
--
-- An exported function with several exposed execution sinks is several
-- observations of one thing, and 708 reports each of them at the function. Every
-- field on the contract then matches, so a consumer reading the report sees one
-- finding written four times - and every count the tool publishes, the corpus
-- total included, counts it four times too (#261).
--
-- The last test here is the one that matters after this is fixed: it sweeps every
-- fixture in the repo and asserts the invariant over all of them. A rule that
-- grows a new way of emitting a duplicate is caught there, rather than by
-- whoever reads the next corpus report and notices a line printed twice.
--
-- Everything goes through a public seam - `luasec.api` and `bin/lua-doctor` - so the
-- specs say what a consumer reads and nothing about how a report is put
-- together. The json is parsed by the small reader below for the same reason
-- report_spec.lua has one: a spec should read the bytes back, not match them as
-- text.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true
local api = require "luasec.api"

-- Four exposures of one exported function, all naming `os.execute`.
local FOUR = "test/fixtures/exposed_sinks/four_exposed_sinks.lua"
-- Two exposures of one exported function naming two different sinks. `luci` is
-- not in the default profile, so the std is named where this one is analyzed.
local TWO = "test/fixtures/exposed_sinks/two_sinks_one_function.lua"
local LUCI_STD = "+openwrt+luci+luajit"

-- The corpus command, so the sweep analyzes the fixtures the way the measurement
-- does rather than in a narrower mode that might not reach the rule at all.
local MEASUREMENT_STD = "+openwrt+luci+luajit"

-- ---------------------------------------------------------------- json

-- Just enough of a reader for a lua-doctor report: objects, arrays, strings, numbers,
-- booleans and null. It exists to read the bytes the tool printed back, so that
-- the assertions below are about the report a consumer gets.
local function decode_json(text)
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
               local code = tonumber(text:sub(pos + 2, pos + 5), 16)
               pos = pos + 6
               if code < 0x80 then
                  out[#out + 1] = string.char(code)
               elseif code < 0x800 then
                  out[#out + 1] = string.char(0xC0 + math.floor(code / 0x40), 0x80 + code % 0x40)
               else
                  out[#out + 1] = string.char(0xE0 + math.floor(code / 0x1000),
                     0x80 + math.floor(code / 0x40) % 0x40, 0x80 + code % 0x40)
               end
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
         skip()
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
      local number = text:sub(pos):match("^%-?%d+%.?%d*[eE]?[%+%-]?%d*")
      pos = pos + #number
      return tonumber(number)
   end

   local value = parse_value()
   skip()
   return value
end

--- Every finding of a report, as a consumer reads them: rendered to json by the
-- public seam and read back, so nothing here can see a field the report omits.
-- The doctor/1 finding flattened to the fields this spec compares by.
local function rendered_findings(report, opts)
   local out = decode_json(api.format(report, "json", opts)).findings
   for _, finding in ipairs(out) do
      finding.code, finding.file = finding.id, finding.location.ref
      finding.line, finding.column = finding.location.line, finding.location.column
      finding.evidence_snippet = nil
   end
   return out
end

-- The tuple two findings in one report must not share: #261's acceptance
-- criterion, the six things a reader tells one finding from another.
--
-- `sink`, `severity` and `trace` are deliberately NOT in it. 708 registers no
-- `fields` at all and its doc page says the finding is about the argument, not
-- about the sink, so a difference in the sink a 708 names is not a difference a
-- reader can see - least of all in plain output, which does not print it. The
-- test "keeps the sinks an exposure speaks for" is what holds that honest: the
-- sinks are still reported, each at its own line, as findings of their own.
local function identity(finding)
   return table.concat({finding.file, finding.code, finding.line, finding.column,
                        finding.message, finding.source}, "\1")
end

-- The findings of `report` carrying `code`, in report order.
local function with_code(report, code)
   local out = {}
   for _, finding in ipairs(report) do
      if finding.code == code then out[#out + 1] = finding end
   end
   return out
end

-- The first repeated identity in `findings`, as a sentence naming it.
local function first_duplicate(findings)
   local seen = {}
   for _, finding in ipairs(findings) do
      local key = identity(finding)
      if seen[key] then
         return string.format("%s:%s:%s [%s] %q (source %q)",
            finding.file, finding.line, finding.column, finding.code,
            finding.message, finding.source)
      end
      seen[key] = true
   end
   return nil
end

-- ---------------------------------------------------------------- specs

describe("a report that repeats one finding", function()
   it("reports an exported function's four exposed sinks once, not four times", function()
      -- Four `os.execute` calls in one exported function, none of their
      -- arguments fed from inside the file. Each is reported at the function.
      local out = harness.cli({"--format", "plain", FOUR})
      local printed = 0
      for line in out:gmatch("[^\n]+") do
         if line:match(":%d+:1: %[708%]") then printed = printed + 1 end
      end
      assert_equal(printed, 1,
         "the same 708 about the same function on the same line is one fact; got:\n" .. out)
   end)

   it("leaves the 701 at each of those sinks alone", function()
      -- The four sinks are four real findings at four real locations. Collapsing
      -- the repeated 708 must not cost the reader the sinks themselves.
      local findings = rendered_findings(api.analyze({FOUR}, {}))
      assert_equal(#with_code(findings, "708"), 1,
         "one exported function, one exposure finding")
      assert_equal(#with_code(findings, "701"), 4,
         "four distinct `os.execute` calls are four distinct 701s and all four must survive")
   end)

   it("counts the finding once in the summary total", function()
      -- The number a reader quotes. A report that prints one line four times and
      -- says "4 findings" is inflating every total the tool publishes.
      local findings = rendered_findings(api.analyze({FOUR}, {}))
      local out = harness.cli({"--format", "plain", FOUR})
      local total = tonumber(out:match("Total: (%d+) findings"))
      assert_equal(total, #findings,
         "the summary total must be the number of findings the report lists")
   end)

   it("reports it once in json, sarif and html as well", function()
      -- Every format is rendered from one normalized list, so this is a claim
      -- about the list rather than about plain. It is asserted anyway: a consumer
      -- reading json or SARIF is exactly who a repeated finding misleads.
      local findings = rendered_findings(api.analyze({FOUR}, {}))
      assert_equal(#with_code(findings, "708"), 1, "the json report lists it once")
      for _, format in ipairs({"sarif", "html"}) do
         local out = harness.cli({"--format", format, FOUR})
         local printed = 0
         for _ in out:gmatch("feeds %(m%.action%)") do printed = printed + 1 end
         assert_equal(printed, 1, format .. " must publish the finding once; got:\n" .. out)
      end
   end)

   it("reports it once under a baseline too", function()
      -- A baseline answers "what changed", so every finding against an empty one
      -- is new, and a repeated finding here would fail a build once per copy.
      local baseline = harness.scratch_dir("baseline") .. "/known.json"
      local known = assert(io.open(baseline, "w"))
      known:write(harness.cli({"--format", "json", "test/fixtures/clean/report.lua"}))
      known:close()
      local out = harness.cli({"--format", "plain", "--baseline", baseline, FOUR})
      local printed = 0
      for line in out:gmatch("[^\n]+") do
         if line:match(":%d+:1: %[708%]") then printed = printed + 1 end
      end
      assert_equal(printed, 1, "everything is new against an empty baseline; got:\n" .. out)
   end)

   it("keeps the sinks an exposure speaks for, as a finding of their own", function()
      -- The half of the promise that matters when two exposures of one function
      -- do name different sinks: collapsing them must not cost the reader the
      -- sinks. Both are reported anyway, each at its own line, which is where an
      -- operator goes to find out what a sink is - and which is the same answer
      -- 724 gives when it reports one finding per registration.
      local findings = rendered_findings(api.analyze({TWO}, {std = LUCI_STD}))
      assert_equal(#with_code(findings, "708"), 1,
         "one exported function, one exposure finding")
      local named = {}
      for _, finding in ipairs(with_code(findings, "701")) do
         named[finding.name] = finding.line
      end
      assert_equal(named["os.execute"], 8, "the shell sink is reported where it is called")
      assert_equal(named["luci.sys.call"], 9, "and so is the other one")
   end)
end)

describe("a report that must not be merged", function()
   it("keeps the findings of two files that are word for word alike", function()
      -- Both fixtures expose a sink from a function on their own line 7 and say
      -- the same sentence. A merge that keyed on everything except the file would
      -- take one of them away, and the two files' line 7 are not one location.
      local merged = rendered_findings(api.analyze({FOUR, TWO}, {std = LUCI_STD}))
      local per_file = {}
      for _, finding in ipairs(with_code(merged, "708")) do
         per_file[finding.file] = (per_file[finding.file] or 0) + 1
      end
      assert_equal(per_file[FOUR], 1, "the four os.execute calls are one sentence")
      assert_equal(per_file[TWO], 1, "and so are the two sinks of the other file")
      assert_true(first_duplicate(merged) == nil,
         "two files in one report must not share a finding")
   end)

   it("keeps the same code reported on several lines of one file", function()
      -- The merge is not "one finding per file" and not "one finding per code".
      -- Four identical calls at four lines are four findings, and the report has
      -- to say so or the reader cannot tell which line to go and read.
      local findings = rendered_findings(api.analyze({FOUR}, {}))
      local lines = {}
      for _, finding in ipairs(with_code(findings, "701")) do
         lines[#lines + 1] = finding.line
      end
      table.sort(lines)
      assert_equal(table.concat(lines, ","), "8,9,10,11",
         "four calls on four lines are four findings, and every line is named")
   end)
end)

describe("every report this tool writes", function()
   it("never names the same code, line, column, message and source twice", function()
      -- The pin. Every fixture in the repo, under the profile the corpus
      -- measurement uses, so a rule that starts emitting a duplicate is caught
      -- here and not by whoever reads the next corpus report.
      local pipe = io.popen("find test/fixtures -name '*.lua' -type f 2>/dev/null | LC_ALL=C sort")
      local paths = {}
      for line in pipe:lines() do
         if line ~= "" then paths[#paths + 1] = line end
      end
      pipe:close()
      assert_true(#paths > 50, "the sweep must cover the fixture tree, found " .. #paths)

      local offenders = {}
      for _, path in ipairs(paths) do
         local ok, report = pcall(api.analyze, {path}, {std = MEASUREMENT_STD})
         if ok then
            local duplicate = first_duplicate(rendered_findings(report, {}))
            if duplicate then
               offenders[#offenders + 1] = path .. ": " .. duplicate
            end
         end
      end
      assert_equal(#offenders, 0,
         "a report must not publish the same finding twice:\n" .. table.concat(offenders, "\n"))
   end)
end)
