-- The analysis pipeline behind luasec.api: parse one source, run the rules and
-- the taint engine, cover and expose, finalize, and merge a whole-program run.
-- luasec.api owns the public entry points and option checking; this module is
-- what they call.
local parse_context = require "luasec.engine.parse_context"
local taint_engine = require "luasec.engine.taint"
local codes = require "luasec.rules.codes"
local platform_api = require "luasec.registry.platform_api"
local profiles = require "luasec.registry.profiles"
local rule_context = require "luasec.rules.context"
local rule_registry = require "luasec.rules.registry"
local inline_directives = require "luasec.engine.inline_directives"
local interprocedural = require "luasec.engine.interprocedural"
local whole_program = require "luasec.engine.whole_program"
local rawscan = require "luasec.rules.rawscan"

local pipeline = {}

-- check_source takes a Lua string; the raw scan wants bytes, and the CLI reads
-- files as bytes, so keep the original string rather than the decoder object.
local function source_bytes_string(source)
   return type(source) == "string" and source or nil
end

local function sort_findings(findings)
   table.sort(findings, function(a, b)
      if a.line ~= b.line then return (a.line or 0) < (b.line or 0) end
      if a.column ~= b.column then return (a.column or 0) < (b.column or 0) end
      return tostring(a.code) < tostring(b.code)
   end)
   return findings
end

--- The shape a bad configuration is reported in, from every entry point.
-- The error object, not a message: the entry points return a findings array and
-- a caller iterates it, so `nil` in its place would turn one clear config error
-- into "bad argument #1 to 'ipairs'" somewhere further out.
local function raise_config_error(message)
   error({luasec_config_error = true, message = message}, 0)
end

--- Install the platform profiles and rule files named by `opts`.
-- Returns true, or nil plus a message when a profile or file is unusable.
local function install_registries(opts)
   platform_api.reset()

   if opts.std and opts.std ~= "" then
      local names, add = profiles.split(opts.std)
      if not add then
         -- Explicit list: the base Lua standard is still loaded, but no
         -- platform profile is implied.
      end
      for _, name in ipairs(names) do
         local declaration, err = profiles.load_builtin(name)
         if not declaration then return nil, err end
         platform_api.apply_profile(declaration)
      end
   end

   for _, path in ipairs(opts.rules or {}) do
      local declaration, err = profiles.load_file(path)
      if not declaration then return nil, err end
      platform_api.apply_profile(declaration)
   end

   for _, name in ipairs(opts.sources or {}) do
      platform_api.add_sources({{pattern = name, id = name, name = "declared source",
         confidence = opts.source_confidence or "high"}})
   end

   for _, name in ipairs(opts.sanitizers or {}) do
      platform_api.add_sanitizers("shell", {name})
   end

   return true
end

-- Mirrors the CLI's --ignore/--only/--enable so an in-source `enable` can
-- override them, which is the whole point of allowing directives at all.
local function suppressed_by_options(opts, finding)
   local suppressed = false
   for _, pattern in ipairs(opts.ignore or {}) do
      if inline_directives.code_and_name_match(pattern, finding) then suppressed = true end
   end
   if opts.only then
      local matched = false
      for _, pattern in ipairs(opts.only) do
         if inline_directives.code_and_name_match(pattern, finding) then matched = true end
      end
      if not matched then suppressed = true end
   end
   return suppressed
end

-- --only, --ignore and --enable take code patterns, and a malformed one is
-- checked at the point it is USED rather than before. A pattern that never
-- matches is not an error there, it is a suppression: `--only '[bad'` matched
-- nothing, so every finding was treated as "not selected" and a file with a
-- high-severity RCE came back clean with exit 0. The in-source directive path
-- was fixed for this; the command line was not.
--- The per-file passes over one source string, and the state a whole-program run
-- needs to join this file to the others.
--
-- Returns a result table:
--   findings   what the per-file passes found, before the shape/exposure phase
--   chstate    the parsed program, or nil when the source did not parse
--   state      the taint state the interprocedural pass used, or nil when it did
--              not run, which is also the case api reports as 904
--   expensive  whether the cross-function passes were skipped
--   final      true when the findings are already complete (bytecode triage),
--              so the phases below must not run again
local function analyze_source(source, opts)
   local ok, install_error = install_registries(opts)
   if not ok then
      -- A profile or rule file we cannot load is an operator error, not a
      -- finding about the analyzed code. Fail loudly.
      raise_config_error(install_error)
   end

   local chstate, syntax_error = parse_context.build(source, {max_nodes = opts.max_nodes})

   if not chstate then
      local finding = {
         code = "901",
         line = (syntax_error and syntax_error.line) or 1,
         column = 1,
         end_column = 1,
         severity = "low",
         confidence = "certain",
         name = "parse error",
      }
      finding.message = codes.render(codes.get("901"), finding)
      if syntax_error and syntax_error.msg then
         finding.message = finding.message .. ": " .. tostring(syntax_error.msg)
      end

      local results = {finding}

      -- A file that does not parse is exactly where an attacker would hide a
      -- payload, so the lexical scan still runs on the raw text. Without this,
      -- breaking the parser was a way to get a clean report.
      if not opts.no_raw_scan then
         local ok, raw = pcall(rawscan.scan_source, source_bytes_string(source), opts)
         if ok and type(raw) == "table" then
            for _, raw_finding in ipairs(raw) do
               if raw_finding.code ~= "901" then
                  results[#results + 1] = raw_finding
               end
            end
         end
      end

      return {findings = sort_findings(results), final = true}
   end

   local findings = taint_engine.run(chstate, opts)

   -- The cross-function and exposed-sink passes both visit every call site and
   -- every named function. On a file with tens of thousands of them that is
   -- minutes of work for a heuristic, so above this many lines they are skipped
   -- and 904 says so rather than the report quietly claiming a clean function.
   local expensive = #chstate.lines > (opts.max_function_lines or 4000)

   -- Taint across function boundaries, unless the file is too large for it.
   local state
   if chstate.resolved_locals ~= false and not opts.no_interprocedural and not expensive then
      state = taint_engine.new_state()
      taint_engine.run(chstate, opts, state)
      local seen = {}
      for _, finding in ipairs(findings) do
         seen[table.concat({finding.code, tostring(finding.line), tostring(finding.column)}, "|")] = true
      end
      interprocedural.run(chstate, state, opts)
      for _, finding in ipairs(state.findings) do
         local key = table.concat({finding.code, tostring(finding.line), tostring(finding.column)}, "|")
         if not seen[key] then
            seen[key] = true
            findings[#findings + 1] = finding
         end
      end
   end

   return {findings = findings, chstate = chstate, state = state, expensive = expensive}
end

--- Resolve the shape-only findings against the ones that say more, and report
-- the sinks nothing in this file feeds.
--
-- This runs after any whole-program findings are merged, not before: a proven
-- cross-file flow at a sink has to suppress both the shape-only 701 there and
-- the 708 that said the input was somewhere we could not see.
local function cover_and_expose(result, opts)
   local chstate = result.chstate
   if result.final or not chstate then return result end
   local findings = result.findings

   -- Locations already explained by a stronger finding: a proven flow or an
   -- exposed sink. The shape-only finding at such a location says less, so it is
   -- dropped rather than reported twice.
   local covered = {}
   for _, finding in ipairs(findings) do
      if finding.code == "709" or finding.code == "710" or finding.code == "743" then
         covered[finding.line .. ":" .. finding.column] = true
      end
   end

   -- 708: an exported function whose execution sink nothing in this file feeds.
   -- The sink exists; the input lives somewhere we cannot see.
   -- `result.expensive`, not a bare `expensive`. This function has no local by
   -- that name, so the test read a GLOBAL that is always nil, and the 708 pass
   -- was never actually skipped: a file over the line cap still paid for the
   -- exposed-sink walk, which is the minutes-long one the cap exists to avoid.
   if chstate.resolved_locals ~= false and not opts.no_interprocedural
         and opts.report_exposed_sinks ~= false and not result.expensive then
      local function sink_key(exposed)
         if not (exposed.sink_line and exposed.sink_offset) then return nil end
         local start = exposed.sink_offset - (chstate.line_offsets[exposed.sink_line] or 0) + 1
         return exposed.sink_line .. ":" .. math.max(1, start)
      end

      for _, exposed in ipairs(interprocedural.exposed_sinks(chstate, opts)) do
         local key = sink_key(exposed)
         if not (key and covered[key]) then
            if key then
               covered[key] = true
            end

            local spec = codes.get("708")
            -- 708 replaces the shape-only finding at this sink, so it carries
            -- that sink's severity rather than a lower one of its own.
            local sink_spec = codes.get(exposed.code)
            local finding = {
               code = "708",
               line = exposed.function_node.line or 1,
               column = math.max(1, exposed.function_node.offset or 1),
               end_column = math.max(1, exposed.function_node.offset or 1),
               severity = (sink_spec and sink_spec.severity) or spec.severity,
               confidence = "low",
               cwe = spec.cwe,
               name = exposed.name,
               sink = exposed.path,
               exposed_as = exposed.name,
            }
            finding.message = codes.render(spec, finding)
            findings[#findings + 1] = finding
         end
      end
   end

   local deduped = {}
   for _, finding in ipairs(findings) do
      local shape_only = finding.code == "701" or finding.code == "702"
         or finding.code == "703" or finding.code == "704"
      if not (shape_only and covered[finding.line .. ":" .. finding.column]) then
         deduped[#deduped + 1] = finding
      end
   end
   result.findings = deduped
   return result
end

--- The per-file findings that do not depend on any other file: 904 for a file
-- the per-file passes could only approximate, the rule modules, sorting, and the
-- in-source directives.
local function finalize(result, opts)
   local findings = result.findings
   local chstate = result.chstate
   if result.final or not chstate then return findings end
   local expensive = result.expensive

   if expensive then
      findings[#findings + 1] = {
         code = "904", line = 1, column = 1, end_column = 1,
         severity = codes.get("904").severity, confidence = "certain",
         cwe = "CWE-0", name = "very large file",
         node_count = chstate.node_count, mode = "no cross-function analysis",
         message = codes.render(codes.get("904"), {name = "very large file"})
            .. "; cross-function and exposed-sink analysis were skipped",
      }
   end

   if chstate.resolved_locals == false then
      findings[#findings + 1] = {
         code = "904", line = 1, column = 1, end_column = 1,
         severity = codes.get("904").severity, confidence = "certain",
         cwe = "CWE-0", name = "large file",
         node_count = chstate.node_count, mode = "approximate",
         message = codes.render(codes.get("904"), {name = "large file"}),
      }
   end

   -- Rule modules see the same parsed program, after the dataflow pass.
   -- The decoder object is not a string, so `source_bytes` is what a snippet
   -- can actually be sliced out of.
   local ctx = rule_context.new(chstate, chstate.source_bytes, opts)
   for _, detector in ipairs(rule_registry.detectors()) do
      local ok, err = pcall(detector, ctx)
      if not ok then
         findings[#findings + 1] = {
            code = "901", line = 1, column = 1, end_column = 1,
            severity = "low", confidence = "certain",
            name = "rule module",
            message = "a rule failed to run: " .. tostring(err),
         }
      end
   end
   for _, finding in ipairs(ctx.findings) do
      findings[#findings + 1] = finding
   end

   sort_findings(findings)

   -- In-source directives are applied last, so `-- luasec: enable` can undo a
   -- config-level suppression.
   -- The table behind the 012 channel is keyed by line, and a line number in
   -- one file says nothing about a line number in the next. Cleared per file:
   -- without it, a malformed directive in file A reports an unreadable pattern
   -- in every file analysed after it in the same process.
   inline_directives.reset_unreadable()
   local directives, problems = inline_directives.parse(chstate)

   for _, problem in ipairs(problems) do
      findings[#findings + 1] = {
         code = "012", line = problem.line, column = 1, end_column = 1,
         severity = "low", confidence = "certain", name = "inline directive",
         message = problem.message,
      }
   end

   if #directives == 0 and #problems == 0 then
      return findings
   end

   local kept = {}
   for _, finding in ipairs(findings) do
      local applicable = {}
      for _, directive in ipairs(directives) do
         if directive.line <= finding.line then
            applicable[#applicable + 1] = directive
         end
      end
      -- A 012 is never filtered by an in-source directive. It IS the finding
      -- that reports a directive we could not read, and `only` takes the
      -- "not selected" branch for a pattern that cannot match - so the
      -- directive suppressed the finding that reports the directive, and
      -- `-- luasec: only [709` turned a file with a hardcoded root password
      -- into a clean report with exit 0. The invariant this whole mechanism
      -- exists to keep is that a broken suppression never hides anything, and
      -- here the broken one hid everything, silently, in the one action that
      -- selects rather than silences.
      if finding.code == "012" then
         kept[#kept + 1] = finding
      elseif inline_directives.allows(applicable, finding,
         suppressed_by_options(opts, finding)) then
         kept[#kept + 1] = finding
      end
   end

   -- Now that the directives have been USED, the patterns that raised are known.
   -- A Lua pattern cannot be validated ahead of use - string.match compiles it as
   -- it walks, so `70(` matches "70" and returns before it reaches the unfinished
   -- capture - which is why this is read here and not at parse time. Appending
   -- to `kept` rather than to `findings`, because `kept` is what this function
   -- returns: the finding was being built and then thrown away.
   -- Only the ones the parse-time probe could not see: it reports most malformed
   -- patterns already, and reporting the same typo twice is noise in a code the
   -- operator has to read.
   local already = {}
   for _, problem in ipairs(problems) do already[problem.line] = true end

   for _, unreadable in ipairs(inline_directives.unreadable()) do
      if not already[unreadable.line] then
         already[unreadable.line] = true
            kept[#kept + 1] = {
            code = "012", line = unreadable.line, column = 1, end_column = 1,
            severity = "low", confidence = "certain", name = "inline directive",
            message = ("luasec directive has an unreadable code pattern '%s'")
               :format(unreadable.pattern),
         }
      end
   end

   return kept
end

--- Join the analyzed files to each other when `opts.whole_program` is set.
--
-- The pass returns its findings already carrying the file they belong to, so
-- each is merged into the result for that file and then goes through the same
-- shape/exposure phase as the per-file ones: a proven cross-file flow has to
-- suppress the shape-only 701 at its sink and the 708 that said the input was
-- somewhere we could not see.
--
-- The per-file state is passed through rather than rebuilt, so the cross-file
-- pass adds one propagate of each file it actually reaches and no more.
local function merge_whole_program(results, opts)
   local contexts, by_path = {}, {}
   for _, result in ipairs(results) do
      if result.chstate then
         contexts[#contexts + 1] = {path = result.path, chstate = result.chstate,
            state = result.state}
         by_path[result.path] = result
      end
   end
   if #contexts < 2 then return nil end

   local extra, diagnostics = whole_program.analyze(contexts, opts)
   if not diagnostics then return nil end

   local seen = {}
   for _, result in ipairs(results) do
      local keys = {}
      for _, finding in ipairs(result.findings) do
         keys[table.concat({finding.code, tostring(finding.line), tostring(finding.column)}, "|")] = true
      end
      seen[result] = keys
   end

   for _, finding in ipairs(extra) do
      local result = by_path[finding.file]
      if result then
         local key = table.concat({finding.code, tostring(finding.line),
            tostring(finding.column)}, "|")
         if not seen[result][key] then
            seen[result][key] = true
            result.findings[#result.findings + 1] = finding
         end
      end
   end

   -- A whole-program run that stopped at a bound has to say so in the report, in
   -- the same code a truncated per-file analysis uses: 904 is this tool's
   -- "the analysis was cut short, the results are not what a full run would
   -- give". A new code would need a registry entry, a doc row and fixtures,
   -- and the semantics of 904 are the ones wanted here.
   for _, bound in ipairs(diagnostics.bounds_hit or {}) do
      local result = (bound.file and by_path[bound.file]) or results[1]
      if result then
         result.findings[#result.findings + 1] = {
            code = "904", line = 1, column = 1, end_column = 1,
            severity = codes.get("904").severity, confidence = "certain",
            cwe = "CWE-0", name = "whole-program " .. tostring(bound.bound),
            mode = "whole-program bound",
            message = "whole-program analysis stopped at its " .. tostring(bound.bound)
               .. " bound in " .. tostring(bound.file)
               .. "; the cross-file results for this scan are incomplete",
         }
      end
   end

   return diagnostics
end

pipeline.raise_config_error = raise_config_error
pipeline.install_registries = install_registries
pipeline.sort_findings = sort_findings
pipeline.analyze_source = analyze_source
pipeline.cover_and_expose = cover_and_expose
pipeline.finalize = finalize
pipeline.merge_whole_program = merge_whole_program

return pipeline
