-- The shape every format is rendered from. One projection, so `plain`, `json`,
-- `sarif` and `html` cannot drift apart, and one order, so a run over unchanged
-- input produces unchanged bytes.
--
-- The contract is documented in docs/sarif.md. The rules it encodes:
--
--   * a finding carries a fixed set of fields, always present, never null;
--   * the order is total, so two runs that visit the same files in a different
--     order still agree byte for byte;
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
function findings.fingerprint(finding)
   return table.concat({finding.code, finding.name, finding.file}, ":")
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

--- Every finding of a report, in report order, on the contract.
function findings.normalize(report, status)
   local out = {}
   for _, raw in ipairs(report or {}) do
      out[#out + 1] = project(raw, status)
   end
   return findings.sort(out)
end

--- The machine-readable document: what version of the contract, which tool, and
-- the findings. `list` is already normalized by `findings.normalize`.
function findings.document(list)
   local s = require("luasec.report.score").summarize(list or {})
   return {
      reportVersion = REPORT_VERSION,
      luasecVersion = require("luasec.version").luasec,
      score = {value = s.score, label = s.label, coverage_gaps = s.coverage_gaps, categories = s.categories},
      findings = list or {},
   }
end

--- Read a document this tool wrote. Returns the findings, or nil plus a
-- message; a baseline file is just a previous run's report.
function findings.read_document(text)
   if type(text) ~= "string" or text:match("^%s*$") then
      return nil, "the file is empty"
   end

   local ok, parsed = pcall(decode, text)
   if not ok then
      return nil, "not a json report: " .. tostring(parsed)
   end
   if type(parsed) ~= "table" or type(parsed.findings) ~= "table" then
      return nil, "not a luasec json report: no findings array"
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
