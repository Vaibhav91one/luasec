-- Whole-program mode: taint that crosses a file boundary.
--
-- The seam under test is `luasec.engine.whole_program.analyze(states, opts)`,
-- which takes the check states a per-file run has already built and returns the
-- extra findings a whole-program run finds. It is the function `api.analyze`
-- calls when `opts.whole_program` is set.
--
-- The states have to be built here rather than taken from `api.check_source`,
-- which returns findings and nothing else. This is the same construction
-- `api.check_source` performs, one per file; once `api.lua` wires the option
-- through, the api-level spec can take its place.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_nil = harness.assert_equal, harness.assert_true, harness.assert_nil

local api = require "luasec.api"
local parse_context = require "luasec.engine.parse_context"
local whole_program = require "luasec.engine.whole_program"

local FIXTURES = "test/fixtures/whole_program"

--- Build the per-file check states `whole_program.analyze` takes, the same way
-- `api.check_source` does: decode, parse, linearize, resolve.
local function states_for(...)
   local states = {}
   for _, name in ipairs({...}) do
      local path = FIXTURES .. "/" .. name
      local handle = assert(io.open(path, "rb"))
      local source = handle:read("*a")
      handle:close()
      states[#states + 1] = {path = path, chstate = parse_context.build(source, {})}
   end
   return states
end

--- Build check states from source text, for the shapes that are impractical to
-- keep as fixtures: a chain long enough to exhaust a bound, and a file with
-- thousands of functions in it.
local function states_from(entries)
   local states = {}
   for _, entry in ipairs(entries) do
      states[#states + 1] = {
         path = entry.path,
         chstate = parse_context.build(entry.source, {max_nodes = entry.max_nodes}),
      }
   end
   return states
end

-- A chain of `depth` modules, each forwarding to the next, with the sink in the
-- last one and the request parameter read in the first.
local function chain_of(depth, directory)
   local entries = {}
   for index = 0, depth - 1 do
      local path = string.format("%s/f%02d.lua", directory, index)
      if index == depth - 1 then
         entries[#entries + 1] = {path = path, source = [[
local M = {}
function M.forward(cmd)
   os.execute(cmd)
end
return M
]]}
      else
         entries[#entries + 1] = {path = path, source = string.format([[
local next_module = require "f%02d"
local M = {}
function M.forward(cmd)
   return next_module.forward(cmd)
end
return M
]], index + 1)}
      end
   end
   entries[#entries + 1] = {path = directory .. "/handler.lua", source = [[
local first = require "f00"
local function go(host)
   first.forward("ping -c1 " .. http.formvalue(host))
end
return go
]]}
   return entries
end

local function codes(findings)
   local out = {}
   for _, finding in ipairs(findings) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

local function only(findings, code)
   for _, finding in ipairs(findings) do
      if finding.code == code then return finding end
   end
end

describe("whole-program: a source in one file reaching a sink in another", function()
   it("reports one finding, in the file that holds the sink", function()
      local states = states_for("cross_file/handler.lua", "cross_file/util.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "709",
         "the source and the sink are one bug split across two files")
      local finding = only(findings, "709")
      assert_equal(finding.file, FIXTURES .. "/cross_file/util.lua",
         "the finding belongs to the file that executes, not the one that reads the request")
      assert_equal(finding.line, 5, "os.execute is on line 5 of util.lua")
   end)

   it("names the file every step of the trace is in", function()
      local states = states_for("cross_file/handler.lua", "cross_file/util.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      local finding = only(findings, "709")
      assert_true(#finding.trace >= 2, "a source step and a sink step at least")
      for _, step in ipairs(finding.trace) do
         assert_true(step.file ~= nil,
            "a line number alone does not place a step when the flow crosses files")
      end
      assert_equal(finding.trace[1].kind, "source")
      assert_equal(finding.trace[1].file, FIXTURES .. "/cross_file/handler.lua",
         "http.formvalue is read in handler.lua")
      assert_equal(finding.trace[#finding.trace].kind, "sink")
      assert_equal(finding.trace[#finding.trace].file, FIXTURES .. "/cross_file/util.lua",
         "os.execute is in util.lua")
   end)

   it("says which file the untrusted data came from", function()
      local states = states_for("cross_file/handler.lua", "cross_file/util.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      local finding = only(findings, "709")
      assert_equal(finding.whole_program.from, FIXTURES .. "/cross_file/handler.lua")
      assert_equal(finding.whole_program.into, FIXTURES .. "/cross_file/util.lua")
      assert_match(finding.message, "handler%.lua",
         "the report has to say where the data entered, not just where it landed")
   end)
end)

describe("whole-program mode: off by default", function()
   it("reports nothing for a source in one file and a sink in another", function()
      local report = api.analyze({
         FIXTURES .. "/cross_file/handler.lua",
         FIXTURES .. "/cross_file/util.lua",
      }, {})

      for _, finding in ipairs(report) do
         assert_true(finding.code ~= "709",
            "the request parameter and the os.execute are in different files, and "
               .. "a per-file run cannot see that they are one bug: " .. finding.message)
      end
      -- What it does report is that the sink is exposed: M.run is exported and
      -- nothing in util.lua feeds it, so the input lives somewhere the per-file
      -- run cannot see. That is the honest answer, and it is what --whole-program
      -- is for.
      local exposure = only(report, "708")
      assert_true(exposure ~= nil, "the exposed sink is still reported without the option")
      assert_equal(exposure.file, FIXTURES .. "/cross_file/util.lua")
   end)
end)

describe("whole-program mode: shapes it has to survive", function()
   it("adds nothing to a flow that is already inside one file", function()
      local states = states_from({{path = "/single/selfcontained.lua", source = [[
local function run(cmd)
   os.execute(cmd)
end
local function go()
   run("ping -c1 " .. http.formvalue("host"))
end
return go
]]}})
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "",
         "the per-file pass already reported this one; reporting it twice would "
            .. "make a fixed bug look like two")
   end)

   it("skips a file that has no check state", function()
      local states = states_for("cross_file/handler.lua", "cross_file/util.lua")
      states[#states + 1] = {path = "unparseable.lua", chstate = nil}
      states[#states + 1] = {path = "not_a_state.lua", chstate = "nonsense"}

      local findings = whole_program.analyze(states, {whole_program = true})
      assert_equal(codes(findings), "709",
         "one unreadable file does not stop the ones that can be joined")
   end)

   it("returns nothing when fewer than two files are in the set", function()
      local states = states_for("cross_file/util.lua")
      local findings, diagnostics = whole_program.analyze(states, {whole_program = true})

      assert_equal(#findings, 0)
      assert_equal(diagnostics.files, 1)
   end)

   it("returns nothing when there are no files at all", function()
      local findings, diagnostics = whole_program.analyze({}, {whole_program = true})
      assert_equal(#findings, 0)
      assert_equal(diagnostics.files, 0)
   end)
end)

describe("whole-program mode: cost", function()
   -- One module of many small functions is the shape that turns an accidental
   -- O(functions x lines) walk into minutes, and it is what a generated or
   -- minified firmware file looks like. `max_nodes` keeps the parse itself out
   -- of the way so the number measured is this pass's.
   local function modules(copies)
      local states = {}
      for index = 1, copies do
         local body = {"local M = {}"}
         for number = 1, 4000 do
            body[#body + 1] = string.format("function M.m%d_%d(x) return x end", index, number)
         end
         body[#body + 1] = "return M"
         states[#states + 1] = {
            path = string.format("/cost/handler%d.lua", index),
            chstate = parse_context.build(string.format([[
local big = require "big%d"
local function go(host)
   big.m%d_1("ping -c1 " .. http.formvalue(host))
end
return go
]], index, index), {}),
         }
         states[#states + 1] = {
            path = string.format("/cost/big%d.lua", index),
            chstate = parse_context.build(table.concat(body, "\n"), {max_nodes = 20000}),
         }
      end
      return states
   end

   local function seconds(states)
      local started = os.clock()
      whole_program.analyze(states, {whole_program = true})
      return os.clock() - started
   end

   it("indexes a module of four thousand functions without slowing to a crawl", function()
      local elapsed = seconds(modules(1))
      assert_true(elapsed < 2,
         ("indexing and resolving one 4000-function module took %.1fs"):format(elapsed))
   end)

   it("scales with the number of files rather than their square", function()
      -- Wall clock at this size is dominated by the clock's own resolution, so
      -- the claim is made in work: the index visits every item once and a call
      -- site is checked once per round. Quadratic would multiply both by the
      -- number of files as well.
      local _, one = whole_program.analyze(modules(1), {whole_program = true})
      local _, four = whole_program.analyze(modules(4), {whole_program = true})

      assert_true(four.items_scanned < one.items_scanned * 5,
         ("four modules scanned %d items against %d for one, which is more than "
            .. "linear in the number of files")
            :format(four.items_scanned, one.items_scanned))
      assert_true(four.site_checks < one.site_checks * 5,
         ("four modules checked %d call sites against %d for one")
            :format(four.site_checks, one.site_checks))
      assert_true(four.rounds <= one.rounds + 1,
         "rounds are a property of the module graph's depth, not of its size")
   end)
end)

describe("whole-program mode: bounds", function()
   it("says so when it stops before the fixpoint settles, instead of stopping quietly", function()
      local states = states_from(chain_of(8, "/scan/chain"))
      local findings, diagnostics = whole_program.analyze(states, {
         whole_program = true, whole_program_max_rounds = 2,
      })

      local hit
      for _, bound in ipairs(diagnostics.bounds_hit) do
         if bound.bound == "fixpoint rounds" then hit = bound end
      end
      assert_true(hit ~= nil,
         "two rounds cannot settle an eight-module chain, and a run that gave up has to admit it")
   end)

   it("reaches a sink in a chain as long as the bound allows", function()
      local states = states_from(chain_of(6, "/scan/ok"))
      local findings, diagnostics = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "709")
      assert_equal(#diagnostics.bounds_hit, 0,
         "a six-module chain is within the default bound and must be silent about it")
      assert_equal(only(findings, "709").file, "/scan/ok/f05.lua")
   end)

   it("marks a finding whose file had more call sites than the bound allowed", function()
      local states = states_from({
         {path = "/scan/many/handler.lua", source = [[
local util = require "util"
local function go(host)
   util.run("ping -c1 " .. http.formvalue(host))
   util.run("traceroute " .. http.formvalue(host))
end
return go
]]},
         {path = "/scan/many/util.lua", source = [[
local M = {}
function M.run(cmd)
   os.execute(cmd)
end
return M
]]},
      })
      local findings, diagnostics = whole_program.analyze(states, {
         whole_program = true, whole_program_max_sites = 1,
      })

      assert_equal(codes(findings), "709")
      local finding = only(findings, "709")
      assert_equal(table.concat(finding.whole_program.bounds_hit, ","), "call sites",
         "the file's second call site was never looked at, so the flow may be "
            .. "incomplete and has to say so")
      assert_match(finding.message, "may be incomplete")
   end)
end)

describe("whole-program mode: a file that was only analyzed approximately", function()
   it("does not present a flow through one as a proven one", function()
      -- `max_nodes` below the file's node count is what makes parse_context skip
      -- flow-sensitive dataflow, which is the condition api reports as 904.
      local states = states_from({
         {path = "/approx/handler.lua", source = [[
local util = require "util"
local function go(host)
   util.run("ping -c1 " .. http.formvalue(host))
end
return go
]]},
         {path = "/approx/util.lua", max_nodes = 4, source = [[
local M = {}
function M.run(cmd)
   os.execute(cmd)
end
return M
]]},
      })
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "709",
         "the flow is real and the sink is reachable, so the finding stands")
      local finding = only(findings, "709")
      assert_equal(table.concat(finding.whole_program.approximate, ","), "/approx/util.lua",
         "the file that carries the flow is the one that was analyzed approximately")
      assert_equal(finding.confidence, "high",
         "http.formvalue is a certain source and code 709 is never more than high, "
            .. "so a flow through an approximately analyzed file loses the step it had")
      assert_match(finding.message, "reduced precision",
         "an approximate cross-file flow must not read as a proven one")
   end)

   it("says nothing about a file analyzed exactly", function()
      local states = states_for("cross_file/handler.lua", "cross_file/util.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      local finding = only(findings, "709")
      assert_equal(#finding.whole_program.approximate, 0)
      assert_equal(finding.confidence, "certain",
         "an exactly analyzed file gives no reason to weaken anything")
      assert_no_match(finding.message, "reduced precision")
   end)
end)

describe("whole-program mode: a crossing with nothing untrusted in it", function()
   it("stays silent when the only cross-file call is a constant", function()
      local states = states_for("constant/handler.lua", "constant/util.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "",
         "following a require edge must not turn every argument into untrusted data")
   end)
end)

describe("whole-program mode: matching a module whose layout is not the scan's", function()
   it("does not guess from a basename unless asked to", function()
      local states = states_for("renamed/handler.lua", "renamed/util.lua")
      local findings, diagnostics = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "",
         "vendor.net.util names nothing in this set, and matching it to the one "
            .. "file called util.lua would be a guess about the loader's path")
      assert_equal(diagnostics.modules > 0, true)
   end)

   it("follows a unique basename when the caller opts in, and says it matched by name", function()
      local states = states_for("renamed/handler.lua", "renamed/util.lua")
      local findings = whole_program.analyze(states, {
         whole_program = true, whole_program_basename = true,
      })

      assert_equal(codes(findings), "709")
      local finding = only(findings, "709")
      assert_equal(finding.whole_program.module_match, "basename",
         "a name match is an inference about the loader's search path, and the "
            .. "finding must not present it as a fact about the layout")
      assert_match(finding.message, "matched by name")
   end)

   it("still refuses when two scanned files share the basename", function()
      local states = states_for("renamed/handler.lua", "renamed/util.lua",
         "missing_module/util.lua")
      local findings = whole_program.analyze(states, {
         whole_program = true, whole_program_basename = true,
      })

      assert_equal(codes(findings), "",
         "two files answer to the name and which one the loader picks depends on "
            .. "a search path this index does not have")
   end)
end)

describe("whole-program mode: two files feeding one sink", function()
   it("names the file each source step is in", function()
      local states = states_from({
         {path = "/two/alpha.lua", source = [[
local util = require "util"
local function go(host)
   util.run("ping -c1 " .. http.formvalue(host))
end
return go
]]},
         {path = "/two/beta.lua", source = [[
local util = require "util"
local function go(name)
   util.run("ping -c1 " .. os.getenv(name))
end
return go
]]},
         {path = "/two/util.lua", source = [[
local M = {}
function M.run(cmd)
   os.execute(cmd)
end
return M
]]},
      })
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "709")
      local finding = only(findings, "709")
      local source_files = {}
      for _, step in ipairs(finding.trace) do
         if step.kind == "source" then source_files[#source_files + 1] = step.file end
      end
      table.sort(source_files)
      assert_equal(table.concat(source_files, ","), "/two/alpha.lua,/two/beta.lua",
         "two files read untrusted data into this sink and the trace has to say "
            .. "which is which, not name whichever was visited first")
   end)

   it("still names a real file when one source API feeds a sink from two files", function()
      -- A taint set holds one descriptor per source id, so the second file's
      -- http.formvalue collapses into the first one's. The finding then names one
      -- of the two, which is still true: that file's data does reach the sink.
      local states = states_from({
         {path = "/one/alpha.lua", source = [[
local util = require "util"
local function go(host)
   util.run("ping -c1 " .. http.formvalue(host))
end
return go
]]},
         {path = "/one/beta.lua", source = [[
local util = require "util"
local function go(host)
   util.run("traceroute " .. http.formvalue(host))
end
return go
]]},
         {path = "/one/util.lua", source = [[
local M = {}
function M.run(cmd)
   os.execute(cmd)
end
return M
]]},
      })
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "709")
      local finding = only(findings, "709")
      local origin = finding.whole_program.from
      assert_true(origin == "/one/alpha.lua" or origin == "/one/beta.lua",
         ("the finding names %s, which is neither of the files that read the "
            .. "request"):format(tostring(origin)))
      assert_equal(finding.trace[1].file, origin)
   end)
end)

describe("whole-program mode: termination", function()
   it("terminates when two files require each other", function()
      local states = states_for("cycle/handler.lua", "cycle/left.lua", "cycle/right.lua")
      local started = os.clock()
      local findings = whole_program.analyze(states, {whole_program = true})
      local elapsed = os.clock() - started

      assert_true(elapsed < 5,
         ("a require cycle took %.1fs: taint only grows, so a cycle cannot feed "
            .. "itself, but the loop has to notice"):format(elapsed))
      assert_equal(codes(findings), "709",
         "the injection is still found, the cycle only has to be survived")
   end)

   it("terminates on a module that requires itself", function()
      local states = states_for("self_require/handler.lua", "self_require/util.lua")
      local started = os.clock()
      local findings = whole_program.analyze(states, {whole_program = true})
      local elapsed = os.clock() - started

      assert_true(elapsed < 5, ("a self-require took %.1fs"):format(elapsed))
      assert_equal(codes(findings), "709",
         "the self-require is not a reason to miss the bug")
   end)
end)

describe("whole-program mode: what it will not join", function()
   it("reports nothing when the required module is not in the analyzed set", function()
      local states = states_for("missing_module/handler.lua", "missing_module/util.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "",
         "util.lua has the sink and handler.lua has the source, but the handler "
            .. "requires a module that is not in the scan. Joining them anyway "
            .. "would be a guess about a file we have not read.")
   end)

   it("reports nothing when the required name is computed at run time", function()
      local states = states_for("computed_name/handler.lua", "cross_file/util.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "",
         "require(name) names nothing an index can hold; 705 reports the computed name")
   end)
end)

describe("whole-program mode: a flow crossing more than one boundary", function()
   it("follows a pass-through in a second file to the sink in a third", function()
      local states = states_for("chain/entry.lua", "chain/middle.lua", "chain/sink.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "709")
      local finding = only(findings, "709")
      assert_equal(finding.file, FIXTURES .. "/chain/sink.lua",
         "one finding, at the sink")
      assert_equal(table.concat(finding.whole_program.files, ","), table.concat({
         FIXTURES .. "/chain/sink.lua",
         FIXTURES .. "/chain/middle.lua",
         FIXTURES .. "/chain/entry.lua",
      }, ","), "the flow crosses all three files, sink first")
      assert_equal(finding.trace[1].file, FIXTURES .. "/chain/entry.lua",
         "http.formvalue is read in entry.lua")
      assert_equal(finding.trace[#finding.trace].file, FIXTURES .. "/chain/sink.lua")
   end)
end)

describe("whole-program mode: the module shapes firmware uses", function()
   it("follows a module that is a single function", function()
      local states = states_for("callable/handler.lua", "callable/runner.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "709")
      assert_equal(only(findings, "709").file, FIXTURES .. "/callable/runner.lua")
   end)

   it("follows a module declared with the Lua 5.1 module call", function()
      local states = states_for("declared/handler.lua", "declared/legacy.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "709")
      local finding = only(findings, "709")
      assert_equal(finding.file, FIXTURES .. "/declared/legacy.lua")
      assert_equal(finding.whole_program.module_match, "module()",
         "the file declares the module name itself, which is a stronger claim "
            .. "than a path suffix and not an inference at all")
      assert_no_match(finding.message, "matched by name")
   end)

   it("follows a module field bound to a local function", function()
      local states = states_for("alias/handler.lua", "alias/util.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "709")
      local finding = only(findings, "709")
      assert_equal(finding.file, FIXTURES .. "/alias/util.lua")
      assert_equal(finding.line, 5, "os.execute is on line 5 of util.lua")
   end)

   it("follows a module a package.preload entry defines", function()
      local states = states_for("preload/handler.lua", "preload/preloaded.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "709",
         "the loader is handed the module by the preload entry, and nothing "
            .. "in the set is named preloaded_util")
      local finding = only(findings, "709")
      assert_equal(finding.file, FIXTURES .. "/preload/preloaded.lua")
      assert_equal(finding.line, 7, "os.execute is on line 7 of preloaded.lua")
   end)
end)

describe("whole-program mode: a required module's function return is followed", function()
   it("follows a module field return bound to a local before use", function()
      local states = states_for("cross_return/handler_local.lua", "cross_return/idmod.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "709")
      local finding = only(findings, "709")
      assert_true(finding.file:match("handler_local.lua$"),
         "the sink is in handler_local.lua, so the finding lives there")
   end)

   it("follows a module field return used as a nested call argument", function()
      local states = states_for("cross_return/handler_nested.lua", "cross_return/idmod.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "709")
      local finding = only(findings, "709")
      assert_true(finding.trace[1].file:match("handler_nested.lua$"),
         "http.formvalue is read in handler_nested.lua")
      local seen_idmod = false
      for _, f in ipairs(finding.whole_program.files) do
         if f:match("idmod.lua$") then seen_idmod = true end
      end
      assert_true(seen_idmod,
         "the flow crossed into idmod.lua and the finding must name it")
   end)

   it("stays silent when the only call across the boundary is a constant", function()
      local states = states_for("cross_return/handler_constant.lua", "cross_return/idmod.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      assert_equal(codes(findings), "",
         "a constant argument through the identity field must not produce 709")
   end)

   it("does not let a cross-file quoting helper raise a 712", function()
      local states = states_for("cross_return/handler_quote.lua", "cross_return/idmod.lua")
      local findings = whole_program.analyze(states, {whole_program = true})

      for _, finding in ipairs(findings) do
         assert_true(finding.code ~= "712",
            "a quoting helper in a module must not raise 712: " .. tostring(finding.code))
         if finding.code == "709" then
            assert_equal(finding.sanitizer, "shell-quoted",
               "the finding should say the data crossed a quoting helper")
         end
      end
   end)
end)

describe("whole-program mode through the public API", function()
   -- Writes into a directory named for the test, so one spec's files cannot be
   -- resolved by another's.
   local function write(dir, name, source)
      os.execute("mkdir -p /tmp/lua-doctor-wp/" .. dir)
      local path = "/tmp/lua-doctor-wp/" .. dir .. "/" .. name
      local handle = assert(io.open(path, "wb"))
      handle:write(source)
      handle:close()
      return path
   end

   it("joins a source in one file to a sink in another when asked", function()
      write("handler", "util.lua", [[
local M = {}
function M.run(cmd)
   os.execute(cmd)
end
return M
]])
      local handler = write("handler", "handler.lua", [[
local util = require "util"
local function go(host)
   util.run("ping -c1 " .. http.formvalue("host"))
end
return go
]])
      -- Both files: the whole-program pass may only resolve a require to a
      -- module it was given.
      local report = api.analyze({handler, "/tmp/lua-doctor-wp/handler/util.lua"},
         {std = "luci", whole_program = true})
      assert_true(#report > 0, "the scan must have produced something to judge")
      local found = {}
      for _, finding in ipairs(report) do
         if finding.code == "709" then found[#found + 1] = finding end
      end
      assert_true(#found >= 1, "the cross-file flow is one finding at the sink: "
         .. #report .. " findings total")
   end)

   it("reports nothing across files without the option", function()
      write("solo", "util.lua", [[
local M = {}
function M.run(cmd)
   os.execute(cmd)
end
return M
]])
      local handler = write("solo", "handler.lua", [[
local util = require "util"
local function go(host)
   util.run("ping -c1 " .. http.formvalue("host"))
end
return go
]])
      local report = api.analyze({handler, "/tmp/lua-doctor-wp/solo/util.lua"}, {std = "luci"})
      for _, finding in ipairs(report) do
         assert_true(finding.code ~= "709",
            "without --whole-program the two files are separate")
      end
   end)

   it("terminates on a module cycle", function()
      write("cycle", "a.lua", "local b = require \"b\"\nreturn {a = function() return b end}\n")
      local b = write("cycle", "b.lua", "local a = require \"a\"\nreturn {b = function() return a end}\n")
      local started = os.clock()
      local ok = pcall(api.analyze, {b}, {whole_program = true})
      assert_true(ok, "a module cycle must not hang or raise")
      assert_true(os.clock() - started < 5, "a module cycle must terminate quickly")
   end)
end)
