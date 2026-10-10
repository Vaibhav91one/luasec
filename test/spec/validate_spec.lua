local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match, assert_no_match =
   harness.assert_equal, harness.assert_true, harness.assert_match, harness.assert_no_match

local api = require "luadoctor.api"

-- The payload runs in a child interpreter, so the specs name one explicitly
-- instead of depending on what happens to be on PATH.
local LUA = os.getenv("LUA_BIN") or "./build/lua-5.4.9/src/lua"

-- A wall clock for the payloads that stop on memory. They take about 0.2s of
-- CPU, under the default 2s clock, but on a loaded machine (other test runs on
-- the same cores) the clock fired first and the verdict named it instead of the
-- memory bound the spec is about (#185). The clock is not their subject.
local SLACK_MS = 30000

describe("payload validator", function()
   it("verdicts a payload that calls os.execute as rce and names the sink", function()
      local verdict = api.validate_payload('os.execute("id")\n', {lua = LUA})

      assert_equal(verdict.verdict, "rce", verdict.exit_reason)
      assert_equal(#verdict.sinks_reached, 1)
      assert_equal(verdict.sinks_reached[1].name, "os.execute")
   end)

   it("verdicts a snippet that only computes a value as benign", function()
      local verdict = api.validate_payload(
         "local total = 0\nfor i = 1, 10 do total = total + i end\nreturn total\n", {lua = LUA})

      assert_equal(verdict.verdict, "benign", verdict.exit_reason)
      assert_equal(#verdict.sinks_reached, 0)
   end)

   it("stops a payload that loops forever and verdicts it timeout, not hung", function()
      local started = os.clock()
      local verdict = api.validate_payload("while true do end\n", {lua = LUA})
      local elapsed = os.clock() - started

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "instruction limit")
      assert_true(elapsed < 10, "the validator took " .. elapsed .. "s to give up")
   end)

   it("kills a payload the instruction limit would never reach and reports timeout", function()
      local started = os.clock()
      local verdict = api.validate_payload("while true do end\n",
         {lua = LUA, timeout_ms = 700, max_instructions = 1e12})
      local elapsed = os.clock() - started

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "wall clock")
      assert_true(elapsed < 8, "the validator took " .. elapsed .. "s to give up")
   end)

   it("records an attempt to read a file instead of reading it", function()
      local secret = "s3cr3t-token-42"
      local path = os.tmpname()
      local file = assert(io.open(path, "wb"))
      file:write(secret)
      file:close()

      local verdict = api.validate_payload(string.format([[
local handle = io.open(%q, "r")
if not handle then return "no-handle" end
local data = handle:read("*a")
handle:close()
return data
]], path), {lua = LUA})

      assert_equal(verdict.verdict, "partial", verdict.exit_reason)
      assert_equal(verdict.sinks_reached[1].name, "io.open")
      assert_no_match(verdict.payload_result or "", secret, "the payload was handed the file contents")

      os.remove(path)
   end)

   it("leaves a file the payload tried to overwrite untouched", function()
      local path = os.tmpname()
      local file = assert(io.open(path, "wb"))
      file:write("original")
      file:close()

      local verdict = api.validate_payload(string.format([[
local handle = io.open(%q, "w")
handle:write("overwritten")
handle:close()
]], path), {lua = LUA})

      local after = assert(io.open(path, "rb"))
      local content = after:read("*a")
      after:close()
      os.remove(path)

      assert_equal(verdict.sinks_reached[1].kind, "fs_write")
      assert_equal(content, "original", "the payload wrote to the filesystem")
   end)

   it("records a native library load as an escape attempt instead of loading it", function()
      local verdict = api.validate_payload([[
local handle, err = package.loadlib("/tmp/does-not-exist.so", "x")
return tostring(handle) .. "|" .. tostring(err)
]], {lua = LUA})

      assert_equal(verdict.verdict, "rce", verdict.exit_reason)
      assert_equal(verdict.escape_attempts[1].name, "package.loadlib")
      assert_match(verdict.payload_result, "disabled", "the payload got a library handle")
   end)

   it("records an attempt to reach the debugger as an escape attempt", function()
      local verdict = api.validate_payload([[
local info, err = debug.getinfo(1)
return tostring(info) .. "|" .. tostring(err)
]], {lua = LUA})

      assert_equal(verdict.escape_attempts[1].name, "debug")
      assert_match(verdict.payload_result, "disabled", "the payload got a debug frame")
   end)

   it("stops the payload when it calls os.exit instead of exiting the validator", function()
      local verdict = api.validate_payload([[
os.exit(0)
return "the payload kept running"
]], {lua = LUA})

      -- Not `rce`. Ending the process is not executing anything, and a verdict that
      -- says a snippet achieved code execution when it only asked to be terminated
      -- is over-strong in the one field an operator is most likely to act on.
      assert_equal(verdict.verdict, "escape", verdict.exit_reason)
      assert_match(verdict.exit_reason, "os%.exit")
      assert_no_match(verdict.payload_result or "", "kept running")
   end)

   it("keeps a process-control escape in the escape list, not only in the verdict", function()
      local verdict = api.validate_payload("os.exit(1)\n", {lua = LUA})

      assert_equal(verdict.escape_attempts[1].name, "os.exit")
      assert_equal(verdict.sinks_reached[1].kind, "process")
   end)

   it("still verdicts a payload that both escapes and executes as rce", function()
      -- `os.exit` stops the payload where it stands, so the two cannot come in
      -- that order. This is the order they can come in: a sink that runs
      -- something and returns, and then the process-control attempt.
      local verdict = api.validate_payload([[
io.popen("id")
os.exit(0)
]], {lua = LUA})

      assert_equal(verdict.verdict, "rce", verdict.exit_reason)
   end)

   it("stops a payload that nests load calls deeper than the limit allows", function()
      local verdict = api.validate_payload([[
-- A chunk that reloads itself, so the nesting grows without the source growing.
_CHUNK = "return load(_CHUNK)()"
return load(_CHUNK)()
]], {lua = LUA})

      assert_no_match(verdict.verdict, "rce", "reaching load is not reaching execution")
      assert_match(verdict.exit_reason, "depth")
      assert_no_match(verdict.payload_result or "", "bottom")
   end)

   it("verdicts a payload that does not parse as an error", function()
      local verdict = api.validate_payload("this is not lua @@@\n", {lua = LUA})

      assert_equal(verdict.verdict, "error")
      assert_match(verdict.exit_reason, "could not be compiled")
      assert_equal(#verdict.sinks_reached, 0)
   end)

   it("names the source in a payload's own error message, as payload text", function()
      local verdict = api.validate_payload("local t = nil\nreturn t.field\n",
         {lua = LUA, name = "candidates/thing.lua"})

      assert_equal(verdict.verdict, "error", verdict.exit_reason)
      -- The message is the payload's own, so the report has to say whose it is
      -- and point it at the file rather than let it read as a lua-doctor message.
      assert_equal(verdict.reason_source, "payload")
      assert_match(verdict.exit_reason, "candidates/thing%.lua")
   end)

   it("stops a payload that tries to allocate a huge string", function()
      local verdict = api.validate_payload(
         [[local chunk = string.rep("a", 1e9) return "allocated " .. #chunk]],
         {lua = LUA, max_memory_kb = 32768})

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "memory ceiling")
      assert_no_match(verdict.payload_result or "", "allocated")
   end)

   it("stops a payload that asks string.format for a huge field width", function()
      local verdict = api.validate_payload([[return string.format("%0999999999d", 1)]],
         {lua = LUA, max_memory_kb = 32768})

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "memory ceiling")
   end)

   it("stops a payload that takes a huge field width from a format argument", function()
      local verdict = api.validate_payload([[return string.format("%*d", 1e9, 1)]],
         {lua = LUA, max_memory_kb = 32768})

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "memory ceiling")
   end)

   it("stops a payload that allocates through string method syntax", function()
      -- `("a"):rep` resolves through the string metatable, not through the
      -- `string` table, so guarding the table alone leaves the allocation open.
      local verdict = api.validate_payload(
         [[local chunk = ("a"):rep(500 * 1024 * 1024) return "allocated " .. #chunk]],
         {lua = LUA, max_memory_kb = 65536})

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "memory ceiling")
      assert_no_match(verdict.payload_result or "", "allocated")
   end)

   it("enforces the memory ceiling at the allocation rather than one window later", function()
      local verdict = api.validate_payload(
         [[local t = {} for i = 1, 4000 do t[i] = ("x"):rep(1024 * 1024) end return #t]],
         {lua = LUA})

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      -- The refusal has to come from the size check in front of the allocation.
      -- When it came from the hook instead, the check only ran every 64 ticks, so
      -- the payload got 6400 instructions - and about a gigabyte - inside one
      -- window before anything looked.
      assert_match(verdict.exit_reason, "string%.rep would allocate %d+ bytes", verdict.exit_reason)
      assert_true(verdict.instructions < 6400,
         "the ceiling was noticed after " .. tostring(verdict.instructions) .. " instructions")
   end)

   it("stops a payload that would double its heap in one table.concat", function()
      -- Every part is live when table.concat runs, and the result is a fresh
      -- string as long as all of them, so without a size check in front of it the
      -- heap can go from the ceiling to twice the ceiling inside one C call.
      local verdict = api.validate_payload([[
local parts = {}
for i = 1, 60000 do parts[i] = ("y"):rep(1024) end
return #table.concat(parts)
]], {lua = LUA, timeout_ms = SLACK_MS})

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "table%.concat would allocate %d+ bytes", verdict.exit_reason)
      assert_no_match(verdict.payload_result or "", "^%d+$", "the concatenation went ahead")
   end)

   it("records running a file of code as an escape attempt", function()
      local verdict = api.validate_payload([[
local chunk, err = dofile("/etc/init.d/some-service")
return tostring(chunk) .. "|" .. tostring(err)
]], {lua = LUA})

      assert_equal(verdict.escape_attempts[1].name, "dofile")
      assert_match(verdict.payload_result, "disabled", "the payload ran a file off disk")
   end)

   it("reports the chain of steps from the payload to the sink it reached", function()
      local verdict = api.validate_payload([[
local built = "os.execute('id')"
local fn = load(built)
fn()
]], {lua = LUA})

      assert_equal(verdict.verdict, "rce", verdict.exit_reason)
      assert_equal(table.concat(verdict.payload_chain, " -> "), "payload -> load -> os.execute")
   end)

   it("reports an error when the interpreter it was told to use does not exist", function()
      local verdict = api.validate_payload("return 1\n", {lua = "/nonexistent/lua"})

      assert_equal(verdict.verdict, "error")
      assert_match(verdict.exit_reason, "interpreter")
   end)

   it("names the source a verdict belongs to, so it traces back to the file", function()
      local path = "test/fixtures/validate/rce.lua"
      local handle = assert(io.open(path, "rb"))
      local source = handle:read("*a")
      handle:close()

      local verdict = api.validate_payload(source, {lua = LUA, name = path})

      assert_equal(verdict.source, path)
      -- The chunk name is what a sink's line number is reported against, so a
      -- verdict has to be traceable to the file the operator passed in.
      assert_equal(verdict.sinks_reached[1].source, path)
      assert_equal(verdict.sinks_reached[1].line, 3)
   end)

   it("traces a sink reached through a loaded chunk back to the file", function()
      -- A chunk the payload built has no file behind it, so the line reported is
      -- the payload's own line that called into it - not a name only the sandbox
      -- knows, which is where this pointed before.
      local verdict = api.validate_payload([[
local built = "os.execute('id')"
local fn = load(built)
fn()
]], {lua = LUA, name = "candidates/built.lua"})

      assert_equal(verdict.verdict, "rce", verdict.exit_reason)
      assert_equal(verdict.sinks_reached[1].source, "candidates/built.lua")
      assert_equal(verdict.sinks_reached[1].line, 3)
   end)

   it("names the interpreter a verdict was produced under", function()
      local verdict = api.validate_payload("return 1\n", {lua = LUA})

      assert_equal(verdict.lua, _VERSION, "the verdict does not say which Lua produced it")
   end)

   it("still bounds a payload whose timeout is a fraction of a second", function()
      -- The watchdog's sleep is a whole number of seconds, so a sub-second
      -- timeout must not become a sleep of a thousandth of a second and kill
      -- the child before the child has had a chance to answer for itself.
      local verdict = api.validate_payload(
         "local total = 0\nfor i = 1, 200000 do total = total + i end\nreturn total\n",
         {lua = LUA, timeout_ms = 500})

      assert_equal(verdict.verdict, "benign", verdict.exit_reason)
   end)

   it("bounds a payload for any timeout, including values that do not divide evenly", function()
      for _, timeout in ipairs({0.5, 1, 250, 1500, 2000.5}) do
         local started = os.clock()
         local verdict = api.validate_payload("while true do end\n",
            {lua = LUA, timeout_ms = timeout, max_instructions = 1e12})
         local elapsed = os.clock() - started

         assert_equal(verdict.verdict, "timeout",
            "timeout_ms=" .. tostring(timeout) .. ": " .. tostring(verdict.exit_reason))
         assert_true(elapsed < 8,
            "timeout_ms=" .. tostring(timeout) .. " took " .. tostring(elapsed) .. "s to give up")
      end
   end)

   it("does not let a payload write to the report channel and forge a verdict", function()
      -- The report channel is the byte stream the parent parses, so this payload
      -- aims at the child's real standard output rather than at `io.write`,
      -- which the sandbox has already replaced with a recorder. It forges every
      -- record type at once, then never finishes, so the sandbox's own records
      -- are never emitted and the forged verdict is the only one there is.
      local verdict = api.validate_payload([[
io.stdout:write("__LUADOCTOR_REPORT__ 3:rce 6:forged 0 1 1\n")
io.stdout:write("__LUADOCTOR_CHAIN__ 9:INJECTED\n")
io.stdout:write("__LUADOCTOR_SINK__ 11:os.execute 0 0 4:exec 0:\n")
io.stdout:flush()
while true do end
]], {lua = LUA, timeout_ms = 700, max_instructions = 1e12})

      assert_no_match(verdict.verdict, "rce", "a forged verdict reached the report")
      assert_no_match(verdict.exit_reason, "forged", "a forged exit reason reached the report")
      assert_equal(#verdict.escape_attempts, 0, "a forged escape attempt reached the report")
      for _, name in ipairs(verdict.payload_chain) do
         assert_no_match(name, "INJECTED", "a forged chain entry reached the report")
      end
      for _, sink in ipairs(verdict.sinks_reached) do
         assert_no_match(sink.name, "os.execute", "a forged sink reached the report")
      end
      assert_match(verdict.exit_reason, "wall clock", "the payload was not stopped by a bound")
   end)

   it("does not let a payload's forged records stand in for the payload's own", function()
      -- Here the payload does finish, so the sandbox's records arrive too. The
      -- forged ones are still not findings: they are payload text, reported as
      -- such, and they are not allowed to add a step to the chain.
      local verdict = api.validate_payload([[
io.stdout:write("__LUADOCTOR_CHAIN__ 9:INJECTED\n")
io.stdout:write("__LUADOCTOR_OUTPUT__ 20:FORGED OPERATOR TEXT\n")
return 1
]], {lua = LUA})

      assert_equal(verdict.verdict, "benign", verdict.exit_reason)
      assert_equal(#verdict.payload_chain, 1)
      assert_equal(verdict.payload_chain[1], "payload")
      assert_equal(#verdict.sinks_reached, 0)
      -- The bytes are not lost: they come back as the payload's own output.
      assert_match(verdict.payload_output, "FORGED OPERATOR TEXT")
   end)

   it("does not let a payload claim to be benign after it reached a sink", function()
      local verdict = api.validate_payload([[
io.stdout:write("__LUADOCTOR_REPORT__ 6:benign 22:forged benign verdict 0 0\n")
os.execute("id")
]], {lua = LUA})

      assert_equal(verdict.verdict, "rce", "the payload's own forged verdict was believed")
      assert_equal(verdict.sinks_reached[1].name, "os.execute")
   end)

   it("captures a payload's own writes instead of letting them reach the caller", function()
      local verdict = api.validate_payload([[
print("PAYLOAD-PRINTED")
io.write("PAYLOAD-WROTE\n")
warn("PAYLOAD-WARNED")
return "done"
]], {lua = LUA})

      assert_equal(verdict.verdict, "benign", verdict.exit_reason)
      assert_match(verdict.payload_output or "", "PAYLOAD%-PRINTED")
      assert_match(verdict.payload_output or "", "PAYLOAD%-WROTE")
      assert_match(verdict.payload_output or "", "PAYLOAD%-WARNED")
   end)

   it("does not hand the payload the analyzer's own environment", function()
      local verdict = api.validate_payload([[return tostring(os.getenv("PATH"))]], {lua = LUA})

      assert_equal(verdict.verdict, "benign", verdict.exit_reason)
      assert_equal(verdict.payload_result, "nil", "the payload read the analyzer's environment")
   end)

   it("kills a payload that allocates faster than any limit inside the child can see", function()
      -- `..` is one C-level concatenation, so the instruction hook cannot run
      -- inside it and the loop that doubles a string never reaches a check: the
      -- whole chain fits in one tick window. Nothing inside the child can bound
      -- this, so the parent has to.
      --
      -- The accumulator is a table field rather than a local, which is also what
      -- keeps it out of reach of the source screen below. This payload is one the
      -- screen does not catch, on purpose: what is being proved here is that the
      -- watchdog holds on its own, and a test that passed only because the
      -- payload was refused before it ran would prove nothing about it.
      local started = os.clock()
      local verdict = api.validate_payload([[
local s = {("a"):rep(1024 * 1024)}
for i = 1, 20 do s[1] = s[1] .. s[1] end
return #s[1]
]], {lua = LUA, timeout_ms = SLACK_MS})
      local elapsed = os.clock() - started

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "resident set")
      assert_true(verdict.rss_kb ~= nil, "the verdict does not say what the child had reached")
      assert_true(verdict.rss_kb > verdict.rss_limit_kb,
         string.format("stopped at %d kB, which is not over the %d kB limit",
            verdict.rss_kb or -1, verdict.rss_limit_kb or -1))
      assert_true(elapsed < 10, "the validator took " .. elapsed .. "s to give up")
   end)

   it("refuses to compile a chunk that concatenates a value with itself", function()
      -- A screen, not a bound: one character of indirection defeats it, which is
      -- why the watchdog above exists. But this shape has no legitimate use in a
      -- payload - doubling a string is only ever memory exhaustion - so refusing
      -- it costs nothing and saves the run.
      local verdict = api.validate_payload([[
local s = ("a"):rep(1024 * 1024)
for i = 1, 20 do s = s .. s end
return #s
]], {lua = LUA})

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "concatenates a value with itself")
      assert_no_match(verdict.payload_result or "", "^%d+$", "the doubling loop ran")
   end)

   it("does not mistake an ordinary accumulator for a self-concatenation", function()
      -- `out = out .. piece` is how firmware builds a response, and a screen that
      -- refused it would refuse the payloads this tool exists to look at.
      local verdict = api.validate_payload([[
local out = ""
for i = 1, 5 do out = out .. "piece" end
return out
]], {lua = LUA})

      assert_equal(verdict.verdict, "benign", verdict.exit_reason)
      assert_equal(verdict.payload_result, "piecepiecepiecepiecepiece")
   end)

   it("applies the same screen to a chunk the payload builds at run time", function()
      -- The screen has to be in front of every chunk, not just the one the driver
      -- pasted in, or a payload gets a second run at it by calling `load`.
      local verdict = api.validate_payload([[
local built = "local s = ('a'):rep(1024 * 1024) s = s .. s return #s"
return tostring(load(built))
]], {lua = LUA})

      assert_match(verdict.exit_reason, "concatenates a value with itself")
   end)

   it("refuses a chunk the payload builds that is larger than the source limit", function()
      -- The payload pasted in is size checked by the driver; a chunk assembled at
      -- run time is not, and compiling one is unbounded work.
      local verdict = api.validate_payload([[
return load(string.rep("return 1\n", 50000))
]], {lua = LUA, max_source_bytes = 4096})

      assert_match(verdict.exit_reason, "larger than the 4096 byte source limit")
   end)

   it("keeps a resident-set kill distinct from a wall-clock kill", function()
      -- Two independent reasons for one child. Reading the wrong one out would
      -- send an operator looking for a hang that never happened.
      local memory = api.validate_payload([[
local s = {("a"):rep(1024 * 1024)}
for i = 1, 20 do s[1] = s[1] .. s[1] end
return #s[1]
]], {lua = LUA, timeout_ms = SLACK_MS})
      local clock = api.validate_payload("while true do end\n",
         {lua = LUA, max_instructions = 1e12, timeout_ms = 500})

      assert_match(memory.exit_reason, "resident set")
      assert_no_match(memory.exit_reason, "wall clock")
      assert_match(clock.exit_reason, "wall clock")
      assert_no_match(clock.exit_reason, "resident set")
   end)

   it("does not kill a payload that only reaches the allocator overhead above its ceiling", function()
      -- The supervisor's threshold has to sit above what an honest payload
      -- reaches, or it reports a memory exhaustion the payload never caused. This
      -- one is refused by the child's own check and peaks at about 1.3x the
      -- ceiling, so the reason has to be the child's and not the supervisor's.
      local verdict = api.validate_payload([[
local parts = {}
for i = 1, 60000 do parts[i] = ("y"):rep(1024) end
return #table.concat(parts)
]], {lua = LUA, timeout_ms = SLACK_MS})

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "table%.concat would allocate")
      assert_no_match(verdict.exit_reason, "resident set",
         "the supervisor killed a payload that stayed inside its limits")
   end)

   it("takes the resident-set threshold as an option rather than a fixed one", function()
      local verdict = api.validate_payload([[
local parts = {}
for i = 1, 60000 do parts[i] = ("y"):rep(1024) end
return #table.concat(parts)
]], {lua = LUA, timeout_ms = SLACK_MS, rss_limit_kb = 20000})

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "resident set", verdict.exit_reason)
      assert_equal(verdict.rss_limit_kb, 20000)
   end)

   it("gives the payload the ordinary base library", function()
      local verdict = api.validate_payload([[
local marker = setmetatable({}, {__tostring = function() return "custom" end})
return tostring(marker) .. "|" .. tostring(getmetatable(marker) ~= nil)
]], {lua = LUA})

      assert_equal(verdict.verdict, "benign", verdict.exit_reason)
      assert_equal(verdict.payload_result, "custom|true")
   end)
end)

describe("payload validator: coroutines", function()
   it("bounds a payload that spins inside a coroutine", function()
      local verdict = api.validate_payload([[
local spin = coroutine.wrap(function() while true do end end)
spin()
]], {lua = LUA, max_instructions = 200000})

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "instruction limit")
   end)
end)

describe("payload validator: precompiled chunks", function()
   it("refuses a precompiled chunk, which would ignore the sandbox environment", function()
      local verdict = api.validate_payload([[
local dumped = string.dump(function() return os.execute end)
local viaDefault, errDefault = load(dumped)
local viaBinary = load(dumped, "=evil", "b")
return tostring(viaDefault) .. "|" .. tostring(errDefault) .. "|" .. tostring(viaBinary)
]], {lua = LUA})

      assert_equal(verdict.sinks_reached[1].name, "load(binary)")
      assert_equal(verdict.sinks_reached[1].kind, "exec")
      assert_match(verdict.payload_result, "disabled", "the payload got a function out of a binary chunk")
   end)
end)
