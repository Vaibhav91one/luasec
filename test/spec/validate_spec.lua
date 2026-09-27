local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_no_match =
   harness.assert_equal, harness.assert_true, harness.assert_no_match

local api = require "luasec.api"

-- The payload runs in a child interpreter, so the specs name one explicitly
-- instead of depending on what happens to be on PATH.
local LUA = os.getenv("LUA_BIN") or "./build/lua-5.4.9/src/lua"

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
      assert_no_match(verdict.result or "", secret, "the payload was handed the file contents")

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
      assert_match(verdict.result, "disabled", "the payload got a library handle")
   end)

   it("records an attempt to reach the debugger as an escape attempt", function()
      local verdict = api.validate_payload([[
local info, err = debug.getinfo(1)
return tostring(info) .. "|" .. tostring(err)
]], {lua = LUA})

      assert_equal(verdict.escape_attempts[1].name, "debug")
      assert_match(verdict.result, "disabled", "the payload got a debug frame")
   end)

   it("stops the payload when it calls os.exit instead of exiting the validator", function()
      local verdict = api.validate_payload([[
os.exit(0)
return "the payload kept running"
]], {lua = LUA})

      assert_equal(verdict.verdict, "rce", verdict.exit_reason)
      assert_match(verdict.exit_reason, "os%.exit")
      assert_no_match(verdict.result or "", "kept running")
   end)

   it("stops a payload that nests load calls deeper than the limit allows", function()
      local verdict = api.validate_payload([[
-- A chunk that reloads itself, so the nesting grows without the source growing.
_CHUNK = "return load(_CHUNK)()"
return load(_CHUNK)()
]], {lua = LUA})

      assert_no_match(verdict.verdict, "rce", "reaching load is not reaching execution")
      assert_match(verdict.exit_reason, "depth")
      assert_no_match(verdict.result or "", "bottom")
   end)

   it("verdicts a payload that does not parse as an error", function()
      local verdict = api.validate_payload("this is not lua @@@\n", {lua = LUA})

      assert_equal(verdict.verdict, "error")
      assert_match(verdict.exit_reason, "could not be compiled")
      assert_equal(#verdict.sinks_reached, 0)
   end)

   it("stops a payload that tries to allocate a huge string", function()
      local verdict = api.validate_payload(
         [[local chunk = string.rep("a", 1e9) return "allocated " .. #chunk]],
         {lua = LUA, max_memory_kb = 32768})

      assert_equal(verdict.verdict, "timeout", verdict.exit_reason)
      assert_match(verdict.exit_reason, "memory ceiling")
      assert_no_match(verdict.result or "", "allocated")
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

   it("records running a file of code as an escape attempt", function()
      local verdict = api.validate_payload([[
local chunk, err = dofile("/etc/init.d/some-service")
return tostring(chunk) .. "|" .. tostring(err)
]], {lua = LUA})

      assert_equal(verdict.escape_attempts[1].name, "dofile")
      assert_match(verdict.result, "disabled", "the payload ran a file off disk")
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

   it("does not let a payload write to the report channel and forge a verdict", function()
      local verdict = api.validate_payload([[
io.write("__LUASEC_REPORT__ 6:benign 13:forged verdict 0 0\n")
os.execute("id")
]], {lua = LUA})

      assert_equal(verdict.verdict, "rce", "the payload's own output was taken for a verdict")
   end)

   it("captures a payload's own writes instead of letting them reach the caller", function()
      local verdict = api.validate_payload([[
print("PAYLOAD-PRINTED")
io.write("PAYLOAD-WROTE\n")
warn("PAYLOAD-WARNED")
return "done"
]], {lua = LUA})

      assert_equal(verdict.verdict, "benign", verdict.exit_reason)
      assert_match(verdict.output or "", "PAYLOAD%-PRINTED")
      assert_match(verdict.output or "", "PAYLOAD%-WROTE")
      assert_match(verdict.output or "", "PAYLOAD%-WARNED")
   end)

   it("does not hand the payload the analyzer's own environment", function()
      local verdict = api.validate_payload([[return tostring(os.getenv("PATH"))]], {lua = LUA})

      assert_equal(verdict.verdict, "benign", verdict.exit_reason)
      assert_equal(verdict.result, "nil", "the payload read the analyzer's environment")
   end)

   it("gives the payload the ordinary base library", function()
      local verdict = api.validate_payload([[
local marker = setmetatable({}, {__tostring = function() return "custom" end})
return tostring(marker) .. "|" .. tostring(getmetatable(marker) ~= nil)
]], {lua = LUA})

      assert_equal(verdict.verdict, "benign", verdict.exit_reason)
      assert_equal(verdict.result, "custom|true")
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
      assert_match(verdict.result, "disabled", "the payload got a function out of a binary chunk")
   end)
end)
