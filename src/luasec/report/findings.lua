-- The shape every format is rendered from. One projection, so `plain`, `json`,
-- `sarif` and `html` cannot drift apart, and one order, so a run over unchanged
-- input produces unchanged bytes.
--
-- The contract is documented in docs/sarif.md. The rules it encodes:
--
--   * a finding carries a fixed set of fields, always present, never null;
--   * the order is total, so two runs that visit the same files in a different
--     order still agree byte for byte;
--   * the same finding appears once: two findings that say the same thing about
--     the same place are one finding, and no rule can publish the same sentence
--     twice;
--   * a finding's identity (its fingerprint) deliberately excludes the line
--     number, so a statement that moved down the file is the same finding;
--   * a taint trace is source-to-sink: every source step, then the sink.
local findings = {}

local REPORT_VERSION = "1.0"

-- The reader this tool ships with, kept beside the contract so a baseline file
-- and a report file are read by the same code. Written for the documents
-- `findings.document` produces: no exponents, no leading zeros. Declared here
-- so `read_document`, which is defined above it, closes over this local rather
-- than over a global of the same name.
local decode

-- Every string field a finding always carries. `f.cwe` and the rest default to
-- the empty string rather than to null, so a consumer never has to ask whether
-- a key is missing or merely empty.
local function text(value)
   if value == nil then return "" end
   return tostring(value)
end

local function number(value)
   return tonumber(value) or 0
end

--- One trace step: kind, the line it is on, its name, and the FILE it is in.
-- The sink step has no name of its own, so it gets the finding's sink rather
-- than an empty one.
--
-- The file is part of the contract. A whole-program flow starts in one file and
-- ends in another, and a consumer that renders every step against the finding's
-- own file sends the reader to the wrong function on the wrong line: the source
-- step of a cross-file 709 is in the handler, not where the sink is.
local function step(raw, fallback_name, fallback_file)
   return {
      kind = text(raw.kind),
      line = number(raw.line),
      name = text(raw.name or fallback_name),
      file = text(raw.file or fallback_file),
   }
end

-- Source-to-sink order. The engine already emits sources before the sink, and
-- this is the guarantee the SARIF thread flow and the HTML trace both rely on,
-- stated once: sources first in the order they were found, then every other
-- step, sink last.
local function normalize_trace(raw, finding)
   if type(raw) ~= "table" or #raw == 0 then return nil end

   local sources, rest, sink = {}, {}, nil
   for _, entry in ipairs(raw) do
      if entry.kind == "source" then
         sources[#sources + 1] = step(entry, nil, finding.file)
      elseif entry.kind == "sink" then
         sink = step(entry, finding.sink, finding.file)
      else
         rest[#rest + 1] = step(entry, nil, finding.file)
      end
   end

   local out = {}
   for _, entry in ipairs(sources) do out[#out + 1] = entry end
   for _, entry in ipairs(rest) do out[#out + 1] = entry end
   if sink then out[#out + 1] = sink end
   return #out > 0 and out or nil
end

--- Project one raw finding onto the contract. Unknown fields the engine happens
-- to carry are dropped: the contract is what a consumer may rely on, and a
-- field that is not in it may change without notice.
local function project(raw, status)
   local out = {
      code = text(raw.code),
      severity = text(raw.severity),
      confidence = text(raw.confidence),
      cwe = text(raw.cwe ~= "CWE-0" and raw.cwe or "CWE-0"),
      message = text(raw.message),
      name = text(raw.name),
      sink = text(raw.sink),
      source = text(raw.source),
      file = text(raw.file),
      line = number(raw.line),
      column = number(raw.column),
      end_column = number(raw.end_column),
   }
   if raw.snippet then out.snippet = text(raw.snippet) end
   -- Whether the data crossed a quoting helper decides if a 709 is exploitable,
   -- so it is part of the contract rather than an engine detail.
   if raw.sanitizer then out.sanitizer = text(raw.sanitizer) end
   if raw.guarded_by then out.guarded_by = text(raw.guarded_by) end
   if type(raw.channels) == "table" and #raw.channels > 0 then
      local channels = {}
      for _, channel in ipairs(raw.channels) do channels[#channels + 1] = text(channel) end
      out.channels = channels
   end
   if raw.exposed_as then out.exposed_as = text(raw.exposed_as) end
   if status then out.status = status end
   out.trace = normalize_trace(raw.trace, out)
   return out
end

-- (file, line, column, code, name) with an optional leading status class, so
-- baseline runs put the new findings before the fixed ones and both blocks are
-- themselves ordered.
local function ordered(a, b)
   if a.status ~= b.status then
      if a.status == nil then return true end
      if b.status == nil then return false end
      return a.status < b.status
   end
   if a.file ~= b.file then return a.file < b.file end
   if a.line ~= b.line then return a.line < b.line end
   if a.column ~= b.column then return a.column < b.column end
   if a.code ~= b.code then return a.code < b.code end
   if a.name ~= b.name then return a.name < b.name end
   if a.message ~= b.message then return a.message < b.message end
   return false
end

--- The order the report is written in, and the reason `--jobs 1` and a
-- different file order on the command line produce the same bytes.
function findings.sort(list)
   table.sort(list, ordered)
   return list
end

--- A finding's identity. It is the code, the name of the thing reported and
-- the file it is in: no line number, so a statement that moved is still the
-- same finding, and a different code for the same name is a different finding.
-- SARIF publishes it as a partial fingerprint and the baseline compares it.
--
-- The doctor/1 fingerprint is 16 lowercase hex characters: the 64-bit FNV-1a
-- hash of `code:name:file`. FNV-1a because Lua has no stdlib hash and this one
-- is eight lines; Lua 5.3+ integers wrap on overflow, which is the mod 2^64 the
-- algorithm wants.
function findings.fingerprint(finding)
   local identity = table.concat({finding.code, finding.name, finding.file}, ":")
   local hash = 0xcbf29ce484222325 -- the FNV offset basis
   for index = 1, #identity do
      hash = (hash ~ identity:byte(index)) * 0x100000001b3
   end
   return string.format("%016x", hash)
end

-- Whether `path` names a directory. Opening it is not the test: POSIX open(2)
-- with O_RDONLY on a directory succeeds on both platforms this ships on, and
-- the read behind it is what fails with EISDIR. So the read is the probe.
--
-- Only a positive answer decides anything. A path that cannot be opened at all
-- is not called a directory here, because it cannot be told apart from a file
-- that was scanned from stdin or written somewhere this run cannot see, and
-- unanchoring one of those costs a real location to guard against a
-- hypothetical platform whose fopen refuses a directory.
local function is_directory(path, memo)
   local cached = memo and memo[path]
   if cached ~= nil then return cached end
   local answer = false
   local handle = io.open(path, "rb")
   if handle then
      answer = not handle:read(0)
      handle:close()
   end
   if memo then memo[path] = answer end
   return answer
end

--- The file a consumer can open for this finding, or nil when it names none.
--
-- Not every finding is about a place in the scanned tree. The aggregate gap
-- over an image whose symlinks all resolve to nothing is about the whole run,
-- and the walk bound and an unlistable directory are too; those carry the
-- scanned directory as their `file`, because the directory is what the run was
-- given. A directory is not a location - nothing opens it - so a format that
-- renders one is publishing a pointer to nowhere, and the finding that says
-- "this run did not fully read your firmware" becomes the one finding a reader
-- cannot get to.
--
-- A renderer asks this before emitting a navigable location, rather than
-- reading `finding.file` itself, so plain and SARIF cannot drift apart on what
-- counts as a place. `memo` is an optional table held for the length of one
-- render: findings arrive grouped by file, so a report of ten thousand
-- findings in a hundred files probes a hundred paths rather than ten thousand.
function findings.open_file(finding, memo)
   local file = finding.file
   if file == nil or file == "" then return nil end
   if is_directory(file, memo) then return nil end
   return file
end

-- The parts a reader tells two findings apart by, each one length-prefixed so
-- that one part's contents cannot be read as the parts beside it: a message that
-- happens to end in a separator is text the tool emitted, not a boundary.
local function part(value)
   local text = value == nil and "" or tostring(value)
   return #text .. ":" .. text
end

--- Two findings are the same finding when they say the same thing about the same
-- place: the file, the code, the location, the sentence and the source.
--
-- Deliberately not "every field the contract happens to carry". `sink` is a field
-- a 708's finding is given by the pipeline and NOT one of the fields 708
-- publishes: codes.lua registers 708 with no `fields` at all, next to 709, which
-- declares `sink`, `source` and `trace` precisely because a consumer uses them.
-- docs/rules/708.md says the same thing in words - "the finding is about the
-- argument, not about the sink".
--
-- So two exposures of one exported function that name different sinks are one
-- sentence said twice, and on a terminal they are indistinguishable: plain
-- renders the sink nowhere, so the two lines come out byte for byte the same.
-- Printing the same line twice is the whole defect, so they collapse.
--
-- Nothing actionable goes with them. Every exposed sink is separately reported as
-- a 701 at its own line - that is where an operator goes to find out what a sink
-- is - and 724 already answers this exact shape the same way: one finding per
-- registration, naming the first sink the handler reaches, with a spec saying so.
--
-- Nor is it blind to anything a reader can act on. Findings that differ in file,
-- code, line, column, message or source are never merged, so two taint findings
-- at one sink from two sources both survive, as does the same code at two lines.
-- `status` is in the key for the same reason: under a baseline, "new" and "fixed"
-- are two different statements about one location.
local function identity(finding)
   return part(finding.file) .. part(finding.code) .. part(finding.line)
      .. part(finding.column) .. part(finding.message) .. part(finding.source)
      .. part(finding.status)
end

--- One finding per distinct finding.
--
-- A report that publishes the same finding twice says the same thing twice. The
-- second copy carries nothing a reader could act on differently, and it inflates
-- every number derived from the report: the summary total, the score, the corpus
-- measurement, the baseline. A report showing one line four times reads as a
-- broken tool and trains the eye to skip past the code rather than read it.
--
-- This runs here rather than in the rule that produced the duplicate because the
-- property is about the published document, and it is then true of every producer
-- - `check_source`, `analyze`, `--jobs`, stdin, a baseline - rather than of the
-- one rule that happens to be wrong today. A rule is free to make an observation
-- several times over; it is the report's job to say it once.
--
-- Which of several equal findings is kept is not observable: they agree on every
-- field a format prints, and `normalize` sorts afterwards.
function findings.distinct(list)
   local out, seen = {}, {}
   for _, finding in ipairs(list or {}) do
      local key = identity(finding)
      if not seen[key] then
         seen[key] = true
         out[#out + 1] = finding
      end
   end
   return out
end

--- Every finding of a report, in report order, on the contract, each distinct
-- finding once.
function findings.normalize(report, status)
   local out = {}
   for _, raw in ipairs(report or {}) do
      out[#out + 1] = project(raw, status)
   end
   return findings.sort(findings.distinct(out))
end

local SEVERITY_ORDER = {critical = 1, high = 2, medium = 3, low = 4, info = 5}

-- The first paragraph of the code's "How to fix" section in docs/rules/<code>.md,
-- or nil when the page is not installed (a rock ships no docs). The root is found
-- from this file's own place in the tree, so the library and the CLI agree.
local function remedy_for(code, memo)
   if memo[code] == nil then
      local path = package.searchpath("luasec.report.findings", package.path) or ""
      local root = path:match("^(.*)/src/luasec/report/findings%.lua$")
      local fix = root and require("luasec.cli.why_cmd").how_to_fix(root, code)
      memo[code] = fix and fix:match("^(.-)\n%s*\n") or fix or false
   end
   return memo[code] or nil
end

--- One finding as the doctor/1 contract (docs/doctor-contract.md section 2) spells
-- it. The fields the old document carried that have no contract key (cwe, name,
-- sink, source, trace...) stay as extra keys, which consumers must ignore.
local function doctor_finding(finding, ctx, memo)
   local json = require "luasec.report.json"
   local file = findings.open_file(finding, memo.dirs)
   local out = {
      id = finding.code,
      fingerprint = findings.fingerprint(finding),
      severity = finding.severity,
      category = require("luasec.rules.categories").of(finding.code) or "other",
      message = finding.message,
      location = {kind = file and "file" or "none", ref = finding.file,
         line = finding.line, column = finding.column},
      remedy = remedy_for(finding.code, memo.remedies) or json.null,
      cwe = finding.cwe, name = finding.name, sink = finding.sink, source = finding.source,
      end_column = finding.end_column, sanitizer = finding.sanitizer,
      guarded_by = finding.guarded_by, channels = finding.channels,
      exposed_as = finding.exposed_as, trace = finding.trace,
   }
   if finding.confidence ~= "" then out.confidence = finding.confidence end
   if finding.snippet then out.evidence = {{ref = "snippet", value = finding.snippet}} end
   if ctx.baseline then out.baseline_state = finding.status end
   return out
end

--- The machine-readable document, the doctor/1 envelope. `list` is already
-- normalized by `findings.normalize`. `ctx.exit_code` is the code this run
-- returns, `ctx.baseline` the {new, unchanged, fixed} counts when a baseline was
-- given.
-- A finding a baseline marked fixed is counted there and not listed.
function findings.document(list, ctx)
   ctx = ctx or {}
   list = list or {}
   local score = require "luasec.report.score"
   local memo = {dirs = {}, remedies = {}}
   local out = {}
   for _, finding in ipairs(list) do
      if finding.status ~= "fixed" then out[#out + 1] = doctor_finding(finding, ctx, memo) end
   end
   table.sort(out, function(a, b)
      if a.severity ~= b.severity then
         return (SEVERITY_ORDER[a.severity] or 9) < (SEVERITY_ORDER[b.severity] or 9)
      end
      if a.id ~= b.id then return a.id < b.id end
      if a.fingerprint ~= b.fingerprint then return a.fingerprint < b.fingerprint end
      -- Same identity, different place: the contract leaves the tie open, so close it.
      if a.location.ref ~= b.location.ref then return a.location.ref < b.location.ref end
      if a.location.line ~= b.location.line then return a.location.line < b.location.line end
      if a.location.column ~= b.location.column then return a.location.column < b.location.column end
      return a.message < b.message
   end)
   local summary = score.summarize(list)
   return {
      schema = "doctor/1",
      tool = "luasec",
      version = require("luasec.version").luasec,
      exit_code = ctx.exit_code or (#out > 0 and 1 or 0),
      score = score.envelope(summary),
      findings = out,
      baseline = ctx.baseline,
      data = {report_version = REPORT_VERSION, categories = summary.categories},
   }
end

--- Read a document this tool wrote (a doctor/1 envelope). Returns it, or nil
-- plus a message; a baseline file is just a previous run's `--json` output.
function findings.read_document(text)
   if type(text) ~= "string" or text:match("^%s*$") then
      return nil, "the file is empty"
   end

   local ok, parsed = pcall(decode, text)
   if not ok then
      return nil, "not a json report: " .. tostring(parsed)
   end
   if type(parsed) ~= "table" or parsed.schema ~= "doctor/1" or type(parsed.findings) ~= "table" then
      return nil, "not a doctor/1 envelope (schema \"doctor/1\" with a findings array); "
         .. "regenerate it with --json"
   end
   return parsed
end

findings.decode = function(text) return decode(text) end

-- The reader itself.
decode = function(text)
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
         if char == "" then error("unterminated string", 0) end
         if char == '"' then pos = pos + 1 break end
         if char == "\\" then
            local escape = text:sub(pos + 1, pos + 1)
            local map = {["\""] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b",
                         f = "\f", n = "\n", r = "\r", t = "\t"}
            if escape == "u" then
               local code = tonumber(text:sub(pos + 2, pos + 5), 16)
               if not code then error("bad \\u escape", 0) end
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
               if not map[escape] then error("bad escape \\" .. escape, 0) end
               out[#out + 1] = map[escape]
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
         if char ~= "," then error("expected , or ] at byte " .. pos, 0) end
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
         if text:sub(pos, pos) ~= ":" then error("expected : at byte " .. pos, 0) end
         pos = pos + 1
         out[key] = parse_value()
         skip()
         local char = text:sub(pos, pos)
         pos = pos + 1
         if char == "}" then break end
         if char ~= "," then error("expected , or } at byte " .. pos, 0) end
      end
      return out
   end

   parse_value = function()
      skip()
      local char = text:sub(pos, pos)
      if char == "" then error("unexpected end of input", 0) end
      if char == "{" then return parse_object() end
      if char == "[" then return parse_array() end
      if char == '"' then return parse_string() end
      if text:sub(pos, pos + 3) == "true" then pos = pos + 4 return true end
      if text:sub(pos, pos + 4) == "false" then pos = pos + 5 return false end
      if text:sub(pos, pos + 3) == "null" then pos = pos + 4 return nil end
      local number = text:match("^%-?%d+%.?%d*", pos)
      if not number or number == "" then error("unexpected input at byte " .. pos, 0) end
      pos = pos + #number
      return tonumber(number)
   end

   local value = parse_value()
   skip()
   return value
end

return findings
