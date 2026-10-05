-- Payload sandbox: the child half.
--
-- This is not a module. validate/driver.lua reads this file and concatenates it
-- into a one-shot `lua -e` program together with the payload and the limits, so
-- it has to bootstrap with nothing but the standard libraries it is about to
-- take away - no `require`, no `package.path`.
--
-- Three rules make the rest of this file auditable:
--
--   1. The real `io`, `os`, `package` and `debug` are captured in locals before
--      the payload runs, and the payload is only ever handed recorders. There is
--      no path from the payload's world back to the originals.
--   2. The payload's world is `env`, a fresh table with no metatable, so `_G`
--      inside the payload is that table and there is no __index fallback to the
--      real globals. `os` and `io` are built from an explicit list of names, not
--      copied, so a member the catalogue does not think about cannot arrive by
--      omission.
--   3. The record channel is not the child's standard output. Records go to the
--      child's standard error, which the parent sends to the record pipe, and the
--      parent points the child's standard output at /dev/null - so even a real
--      handle on stdout could not put a byte in the channel the parent parses.
--      On top of that every record carries a nonce the parent generated and the
--      payload cannot read, so a line that reaches the channel without it is
--      noise and is dropped.

local real_io, real_os, real_debug = io, os, debug
local real_load, real_pcall, real_collectgarbage = load, pcall, collectgarbage
local real_string, real_coroutine, real_table = string, coroutine, table

-- The report channel. `emit` is captured into a local, and the payload is never
-- handed this handle or any way of naming it. `RECORD.write` alone would be the
-- unbound C function, which writes to the default output, so the file is bound
-- here rather than by the caller.
local RECORD = real_io.stderr
local emit = function(first, second) return RECORD:write(first, second) end

-- The dialects the sandbox was written against. A verdict describes the Lua that
-- produced it, so a child running under anything else refuses the payload rather
-- than reporting an outcome it cannot vouch for.
local SUPPORTED_DIALECTS = {["Lua 5.3"] = true, ["Lua 5.4"] = true, ["LuaJIT"] = true}

local DEFAULT_SOURCE = "luasec-payload"

-- The verdict vocabulary the parent speaks.
--
--   exec      the payload reached an execution sink; this is what makes a
--             verdict `rce`
--   process   it tried to control the process it is running in
--   fs_read   it reached data it should not have been able to read
--   fs_write  it reached something it should not have been able to change
--   probe     it probed the sandbox itself
--
-- `escape` marks the calls that try to leave the sandbox rather than to do their
-- job: process control, native code, or the debugger.
--
-- `os.exit` is `process` and not `exec`, and the distinction is the whole reason
-- the kind exists. It ends the process; it runs nothing. Reporting it as `exec`
-- made a snippet that asked to be terminated indistinguishable from one that ran
-- a command, in the single field an operator is most likely to act on. A payload
-- that reaches both still verdicts `rce`, because `exec` outranks `process`.
local CATALOGUE = {
   ["os.execute"]      = {kind = "exec", escape = true},
   ["io.popen"]        = {kind = "exec", escape = true},
   ["package.loadlib"] = {kind = "exec", escape = true},
   ["os.exit"]         = {kind = "process", escape = true},
   ["os.remove"]       = {kind = "fs_write"},
   ["os.rename"]       = {kind = "fs_write"},
   ["os.tmpname"]      = {kind = "fs_write"},
   ["io.open"]         = {kind = "fs_read"},
   ["io.lines"]        = {kind = "fs_read"},
   ["io.input"]        = {kind = "fs_read"},
   ["io.read"]         = {kind = "fs_read"},
   ["io.output"]       = {kind = "fs_write"},
   ["io.tmpfile"]      = {kind = "fs_write"},
   ["dofile"]          = {kind = "exec", escape = true},
   ["loadfile"]        = {kind = "exec", escape = true},
   ["require"]         = {kind = "exec", escape = true},
   ["load(binary)"]    = {kind = "exec", escape = true},
   ["debug"]           = {kind = "probe", escape = true},
   ["collectgarbage"]  = {kind = "probe", escape = true},
}

-- The members of `os` and `io` the payload may have. Everything else is absent
-- rather than blocked, which is the point: `io.stdout` is a real handle on the
-- report channel and the only safe thing to do with it is not to have it. The
-- `io` list is empty on purpose - every member the payload gets is one built
-- below, and a real one (`io.close` and `io.flush` act on the default output
-- file) has no place in here.
--
-- `getmetatable` is in the base library below because payloads use it, and on
-- its own it reaches nothing - but it is also the way to the string metatable,
-- which is why the size guard is installed on that metatable rather than only on
-- the `string` table.
local OS_MEMBERS = {"clock", "date", "difftime", "time", "setlocale"}
local IO_MEMBERS = {}

-- Every limit raises this one sentinel. The payload cannot forge it (it is a
-- local upvalue) and the runner tells a limit stop apart from the payload's own
-- error by identity, not by message.
local LIMIT = {}

local sinks, chain, escapes = {}, {}, {}
local chain_set = {}
local limits, env
local spent, started, ticks, stop_reason = 0, 0, 0, nil
local output, output_bytes = {}, 0
local source_name = DEFAULT_SOURCE

-- Anything the payload writes is captured rather than emitted. The child's
-- standard output is not the report channel, but a payload's bytes still must not
-- reach whoever is reading this tool's output, so the capture is also what the
-- report labels as payload text.
local OUTPUT_LIMIT = 4096

local function capture_output(...)
   if output_bytes >= OUTPUT_LIMIT then return end
   for i = 1, select("#", ...) do
      local piece = tostring((select(i, ...)))
      if output_bytes + #piece > OUTPUT_LIMIT then piece = piece:sub(1, OUTPUT_LIMIT - output_bytes) end
      output[#output + 1] = piece
      output_bytes = output_bytes + #piece
   end
end

-- ------------------------------------------------------------------ reporting

-- One record per line, one field per space, and every field either a bare
-- integer or "<byte-length>:<the bytes>". A value that contains spaces or
-- newlines therefore cannot be mistaken for a field boundary, and control bytes
-- are escaped so a record never spans two lines.
local function text(value)
   return (tostring(value):gsub("[%c]", function(c)
      return string.format("\\x%02x", c:byte())
   end))
end

local function blob(value)
   local encoded = text(value)
   return #encoded .. ":" .. encoded
end

-- The nonce arrives as a global of this program's own environment, which the
-- payload does not get: the payload's _ENV is `env`. It is copied into a local
-- upvalue here so that the payload has no name to read even if it could reach a
-- global, and so a line that lacks it is not a record the parent will parse.
local nonce

local function record(tag, fields)
   local parts = {tag, nonce}
   for _, value in ipairs(fields) do
      parts[#parts + 1] = value
   end
   emit(table.concat(parts, " "), "\n")
end

-- ------------------------------------------------------------------ recording

-- The innermost frame that belongs to the payload rather than to the sandbox.
-- Sandbox functions are loaded with a "=" chunk name and C frames report "[C]",
-- so both are skipped and this never reports a line from inside the sandbox.
local function caller_frame(level)
   level = level or 3
   while true do
      local info = real_debug.getinfo(level, "Sl")
      if not info then return source_name, 0 end
      local source = info.source or ""
      if source ~= "[C]" and not source:match("^=") then
         return source:gsub("^@", ""), info.currentline or 0
      end
      level = level + 1
   end
end

local function add_sink(name, first_argument)
   local source, line = caller_frame(3)
   local spec = CATALOGUE[name] or {}
   local sink = {name = name, kind = spec.kind or "probe", line = line, source = source}
   if first_argument ~= nil then
      sink.arg = text(first_argument):sub(1, 200)
   end
   sinks[#sinks + 1] = sink
   if spec.escape then escapes[#escapes + 1] = sink end
   if not chain_set[name] then
      chain_set[name] = true
      chain[#chain + 1] = name
   end
   return sink
end

-- A handle on a file the sandbox never opened. Its methods are silent on
-- purpose: `io.open` already records that the payload tried, and reading
-- through the handle would report the same act twice.
local function fake_handle()
   return {
      read = function() return "" end,
      write = function() return true end,
      lines = function() return function() return nil end end,
      seek = function() return 0 end,
      setvbuf = function() return true end,
      flush = function() return true end,
      close = function() return true end,
   }
end

-- One of the three standard streams, as the payload sees it. The real ones are
-- file handles on the child's own descriptors, and one of those descriptors is
-- where the records go, so what the payload gets here is not a handle at all:
-- writes land in the same capture as `print`, reads return nothing, and neither
-- can move a verdict.
local function captured_stream()
   return {
      write = function(_, ...)
         capture_output(...)
         return true
      end,
      read = function() return nil end,
      lines = function() return function() return nil end end,
      seek = function() return 0 end,
      setvbuf = function() return true end,
      flush = function() return true end,
      close = function() return true end,
   }
end

-- A blocked call records where it happened, hands back something harmless, and
-- lets the payload carry on so the rest of its behaviour becomes visible.
local function block(name)
   return function(...)
      add_sink(name, (select("#", ...) > 0) and (select(1, ...)) or nil)
      return nil, "sandbox: " .. name .. " is disabled"
   end
end

-- For a library the payload reaches into (`debug.sethook`), so that reading any
-- member is what gets recorded. The member name is the argument, so the sink
-- stays "debug" and the report shows which part it went for.
local function probe_table(name)
   return setmetatable({}, {__index = function(_, key)
      add_sink(name, tostring(key))
      return function() return nil, "sandbox: " .. name .. " is disabled" end
   end})
end

-- `io.open` is the one recorder that has to look at its arguments: a read is a
-- different finding from a write, and a payload that gets a handle back keeps
-- running instead of stopping at the first error.
local function open_recorder()
   return function(path, mode)
      local kind = tostring(mode or "r"):find("[wa+]") and "fs_write" or "fs_read"
      local sink = add_sink("io.open", path)
      sink.kind = kind
      return fake_handle()
   end
end

-- A library the payload can see, built by naming what it may have. This is not a
-- copy of the real one on purpose: a copy hands over every member nobody
-- thought about, and `io.stdout` is one of them - a live handle on the bytes
-- the parent parses. An allowlist cannot leak by omission, so the absence of a
-- name here is the guarantee.
--
-- Names in the catalogue that live under `prefix` are blocked; the rest of the
-- allowlist is passed through, so `os.time` and `os.date` still work.
local function allowed(original, names, prefix)
   local copy = {}
   for _, name in ipairs(names) do
      local value = original[name]
      if value ~= nil then copy[name] = value end
   end
   for name in pairs(CATALOGUE) do
      if name:sub(1, #prefix) == prefix and #name > #prefix then
         local member = name:sub(#prefix + 1)
         copy[member] = name == "io.open" and open_recorder() or block(name)
      end
   end
   return copy
end

-- --------------------------------------------------------------------- limits

-- How many instructions pass between two checks of the hook. Small enough that
-- a short payload still reports a real count, large enough that the hook itself
-- is not the thing being measured. Every tick also reads the heap and the clock,
-- which costs about 0.24us per tick against a 12ms baseline for the whole
-- five million instruction budget.
local INSTRUCTIONS_PER_TICK = 100

-- The instruction budget is counted, not sampled, so a payload cannot spend its
-- way past a check by catching the error and continuing: the counter only grows.
local function stop(reason)
   stop_reason = reason
   error(LIMIT, 0)
end

local function hook()
   spent = spent + INSTRUCTIONS_PER_TICK
   ticks = ticks + 1
   if spent > limits.max_instructions then
      stop(string.format("instruction limit of %d exceeded", limits.max_instructions))
   end
   -- Every tick, and not every sixty-fourth. The window between two checks is
   -- exactly the budget a payload has to allocate past the ceiling, and 6400
   -- instructions of `t[i] = ("x"):rep(1024 * 1024)` is 4GB of it.
   if real_collectgarbage("count") > limits.max_memory_kb then
      stop(string.format("memory ceiling of %dkB exceeded", limits.max_memory_kb))
   end
   if (real_os.clock() - started) * 1000 > limits.timeout_ms then
      stop(string.format("wall clock of %dms exceeded", limits.timeout_ms))
   end
end

-- ------------------------------------------------------------------- the world

local load_depth = 0

-- How much of the ceiling is still unallocated. The memory check cannot run
-- inside a C call, so the functions that can allocate far more than their
-- arguments describe are checked against this before they run: `string.rep`,
-- `string.format` (above) and `table.concat` (below). There is no address space
-- limit to fall back on either - macOS refuses `RLIMIT_AS` - which is why the
-- ceiling is enforced here as well as in the hook.
local function bytes_left()
   return math.max(limits.max_memory_kb - real_collectgarbage("count"), 0) * 1024
end

local function guard_size(name, want)
   if want > bytes_left() then
      stop(string.format("memory ceiling of %dkB exceeded: %s would allocate %d bytes",
         limits.max_memory_kb, name, want))
   end
end

-- An explicit field width is the only unbounded part of a format: without one,
-- a number prints short and a string cannot print longer than it already is.
-- A `*` width takes its value from an argument, so those arguments are counted.
local function format_bound(fmt, ...)
   local want = 0
   for spec in fmt:gmatch("%%[%-%+ #0]*%d+") do
      want = want + tonumber(spec:match("(%d+)$"))
   end
   if fmt:find("%*", 1, true) then
      for i = 1, select("#", ...) do
         local value = select(i, ...)
         if type(value) == "number" then want = want + math.abs(value) end
      end
   end
   return want
end

local function guarded_string()
   local copy = {}
   for k, v in pairs(real_string) do copy[k] = v end
   copy.rep = function(subject, count, separator)
      local size = (tonumber(count) or 0) * (separator and #separator + 1 or #subject)
      guard_size("string.rep", size)
      return real_string.rep(subject, count, separator)
   end
   copy.format = function(fmt, ...)
      guard_size("string.format", format_bound(tostring(fmt), ...))
      return real_string.format(fmt, ...)
   end
   return copy
end

-- The guard goes where a method call actually looks. `("a"):rep(n)` never
-- touches the `string` table: it goes through the metatable every string
-- carries, whose __index is the real `string`. Guarding the table alone left
-- that route wide open, and it is one character of syntax away from the whole
-- allocation the guard exists to refuse. So the guarded copy is installed as the
-- metatable's __index as well, and `string.rep` and `("a"):rep` are the same
-- function from the payload's side of the sandbox.
--
-- The payload is given `getmetatable`, so it can read this metatable, and it can
-- overwrite `__index.rep` to weaken the guard for itself. It cannot put the real
-- `string.rep` back: the real table is a local upvalue, and this is the only
-- route to it, so the worst it can do is lose the ceiling for its own run.
local function install_string_guard()
   local guarded = guarded_string()
   local meta = real_debug.getmetatable("")
   if meta then meta.__index = guarded end
   return guarded
end

local function concat_size(subject, separator, first, last)
   if type(subject) == "string" then return #subject end
   if type(subject) ~= "table" then return 0 end
   local from = tonumber(first) or 1
   local to = tonumber(last) or #subject
   if to < from then return 0 end
   local size = (type(separator) == "string" and #separator or 0) * (to - from + 1)
   for i = from, to do
      local piece = subject[i]
      if type(piece) == "string" then size = size + #piece end
   end
   return size
end

-- `table.concat` is the one standard function left that can turn a heap already
-- at the ceiling into roughly twice the ceiling, in a single C call where the
-- instruction hook cannot see it coming: every part is live, and the result is a
-- fresh string as long as all of them put together. Its result size is the sum
-- of the parts, which is the same walk the real function makes, so it is known
-- before the allocation rather than after it. Measured on this machine: without
-- this check, 60000 one kilobyte parts concatenate into a 60MB result and take
-- the child's peak resident set to 210MB against a 64MB ceiling.
--
-- Everything else in `table` allocates in proportion to something that is already
-- live, so at worst it doubles the set, and the periodic check catches that on
-- the next tick.
local function guarded_table()
   local copy = {}
   for k, v in pairs(real_table) do copy[k] = v end
   copy.concat = function(subject, separator, first, last)
      guard_size("table.concat", concat_size(subject, separator, first, last))
      return real_table.concat(subject, separator, first, last)
   end
   return copy
end

-- Every chunk the payload builds runs one level deeper, so a chunk that reloads
-- itself runs out of room instead of the C stack. The counter is unwound even
-- when the chunk raises, so a payload that catches its way out cannot keep
-- climbing for free.
local function with_depth(fn)
   return function(...)
      load_depth = load_depth + 1
      if load_depth > limits.max_load_depth then
         load_depth = load_depth - 1
         stop(string.format("load nesting depth limit of %d exceeded", limits.max_load_depth))
      end
      local packed = table.pack(real_pcall(fn, ...))
      load_depth = load_depth - 1
      if not packed[1] then error(packed[2], 0) end
      return table.unpack(packed, 2, packed.n)
   end
end

-- `load` stays available - firmware payloads use it to decode strings - but only
-- for text, and only into this sandbox. A binary chunk is refused because Lua
-- ignores the environment argument for one, which would hand the payload the
-- real globals; that refusal is the dropper pattern, so it is recorded as one.
--
-- The mode argument is not enough to spot one: `load` defaults to accepting both,
-- so a precompiled chunk with no mode at all still has to be recognised. Every
-- precompiled chunk starts with the escape byte of the Lua signature.
local function is_precompiled(chunk)
   return type(chunk) == "string" and chunk:sub(1, 1) == "\27"
end

-- The screen for the one allocation the size checks in front of `string.rep`,
-- `string.format` and `table.concat` cannot cover.
--
-- `..` compiles to OP_CONCAT, which is a single C-level call: the instruction hook
-- does not run inside it, and there is no Lua-callable seam in front of it. A
-- payload that writes `s = s .. s` in a loop doubles its heap as many times as the
-- loop will iterate, and the loop's whole work lands inside one instruction tick.
-- Measured with nothing else in the way: 65.6x the ceiling before the parent's
-- resident-set watchdog, and the child's own heap check firing 4096 instructions
-- too late to matter.
--
-- So this refuses the *shape* rather than trying to bound the operation. It is a
-- screen and not a bound, and the difference is not a matter of wording: one
-- character defeats it, `s = s .. (s)` is not caught and neither is
-- `s[1] = s[1] .. s[1]`, and a payload that builds the text at run time and hands
-- it to `load` gets the same screen only because the screen is in front of every
-- chunk. What is left is still bounded - by the parent's watchdog, which is the
-- reason that watchdog exists - and a payload that evades this is stopped there
-- rather than not at all.
--
-- The cost of the screen is a false positive, and it is why the pattern is this
-- narrow: only a bare name on both sides, so `out = out .. piece`, which is how
-- firmware builds a response, is untouched.
local function self_concatenation(text)
   if not text:find("..", 1, true) then return nil end
   -- `()%.%.` is a position capture followed by two literal dots, so the position
   -- is the first of the two and the right operand starts one past the second.
   -- Prepending a blank to the left operand is what makes the name match start on
   -- a word boundary rather than anywhere inside an identifier.
   for at in text:gmatch("()%.%.") do
      local left = (" " .. text:sub(1, at - 1)):match("([%a_][%w_]*)%s*$")
      local right = text:sub(at + 2):match("^%s*([%a_][%w_]*)")
      if left and right and left == right then
         -- Lua has no `string.count`; the second return of gsub is the number of
         -- replacements, which is the line the operator has to look at.
         local line = select(2, text:sub(1, at - 1):gsub("\n", "\n")) + 1
         return left, line
      end
   end
   return nil
end

-- The line the screen tripped on is in the reason, because the point of naming it
-- is that an operator can go and look at it.
local function screen(text)
   local name, line = self_concatenation(text)
   if name then
      stop(string.format(
         "refused to compile a chunk that concatenates a value with itself, at line %d: %s .. %s. "
         .. "`..` is one C-level call that no limit inside this child can preempt, so the doubling is "
         .. "bounded from outside instead", line, name, name))
   end
end

local function guarded_load(chunk, chunkname, mode)
   if type(chunk) == "string" and not chain_set.load then
      chain_set.load = true
      chain[#chain + 1] = "load"
   end

   if is_precompiled(chunk) or (type(mode) == "string" and mode:find("b", 1, true)) then
      add_sink("load(binary)", tostring(chunkname or ""))
      return nil, "sandbox: binary chunks are disabled"
   end

   -- The source the driver pasted in is size checked there, before this program
   -- exists. A chunk assembled at run time is not, and compiling one is
   -- unbounded work, so it is checked here - after the same screen, which is
   -- ahead of every chunk the payload compiles rather than only this one.
   if type(chunk) == "string" then
      screen(chunk)
      if #chunk > limits.max_source_bytes then
         stop(string.format("refused a chunk of %d bytes: larger than the %d byte source limit",
            #chunk, limits.max_source_bytes))
      end
   end

   -- The "=" prefix is what `caller_frame` looks for to recognise a frame that
   -- belongs to the sandbox. A chunk the payload built has no file behind it, so
   -- naming it "=..." means a sink reached inside one is attributed to the
   -- payload's own line that called into it - a place the operator can go and
   -- look - instead of to this generated chunk, which is nowhere on their disk.
   local fn, err = real_load(chunk, "=luasec-generated", "t", env) -- luasec: ignore 703  real_load is load; compiling the screened chunk is the validator's whole job
   if not fn then return nil, err end
   return with_depth(fn)
end

-- Lua's instruction hook belongs to a thread, and a new thread starts with none,
-- so a payload could spin inside a coroutine with the budget never noticing.
-- Every body the payload hands to `coroutine.create` or `coroutine.wrap` re-
-- installs the hook on the thread it is about to run on. Both are needed:
-- `coroutine.wrap` is implemented in C and does not go through `create`.
local function guarded_coroutine()
   local function bounded(fn)
      return function(...)
         real_debug.sethook(hook, "", INSTRUCTIONS_PER_TICK)
         return fn(...)
      end
   end

   local copy = {}
   for k, v in pairs(real_coroutine) do copy[k] = v end
   copy.create = function(fn) return real_coroutine.create(bounded(fn)) end
   copy.wrap = function(fn) return real_coroutine.wrap(bounded(fn)) end
   return copy
end

local function build_env()
   env = {}
   -- The chain starts at the payload itself, so a reader can tell "the payload
   -- called this" from "the sandbox called this".
   chain[1], chain_set.payload = "payload", true
   for _, name in ipairs({"assert", "error", "getmetatable", "setmetatable",
                          "ipairs", "next", "pairs", "pcall",
                          "select", "tonumber", "tostring", "type",
                          "xpcall", "rawequal", "rawget", "rawlen", "rawset",
                          "_VERSION", "utf8", "math"}) do
      env[name] = _G[name]
   end
   env.string = install_string_guard()
   env.table = guarded_table()
   env.coroutine = guarded_coroutine()

   env.os = allowed(real_os, OS_MEMBERS, "os.")
   env.io = allowed(real_io, IO_MEMBERS, "io.")
   -- There is no environment to see: an embedded interpreter usually has none,
   -- and handing the payload the analyzer's own would put the operator's paths
   -- into a report they are about to file or paste.
   env.os.getenv = function() return nil end
   -- `package` is emptied rather than guarded: the searchers are what turn a
   -- module name into a file read, so with them gone `require` cannot reach the
   -- filesystem even if the payload keeps a reference to the real one. What is
   -- left records the attempt.
   env.package = {
      loadlib = block("package.loadlib"),
      preload = {},
      loaded = {},
      path = "",
      cpath = "",
      config = "/\n;\n?\n!\n-\n",
   }
   -- `os.exit` must stop the payload the way the real one would, and `debug` and
   -- `collectgarbage` are recorders so that the payload cannot turn the hook or
   -- the garbage collector off from under us.
   env.os.exit = function(...)
      add_sink("os.exit", (select("#", ...) > 0) and (select(1, ...)) or nil)
      stop("the payload called os.exit")
   end
   env.debug = probe_table("debug")
   env.collectgarbage = block("collectgarbage")
   env.require = block("require")
   env.dofile = block("dofile")
   env.loadfile = block("loadfile")
   env.load = guarded_load
   env.loadstring = guarded_load
   env.print = function(...)
      capture_output(...)
      capture_output("\n")
   end
   -- The three standard streams are the capture, not the report channel. The
   -- report channel is the child's standard error, and no member of this table
   -- is a handle on it.
   env.io.stdout = captured_stream()
   env.io.stderr = captured_stream()
   env.io.stdin = captured_stream()
   -- Writing to the payload's own output is harmless, so it is not a sink, but
   -- the bytes must still go to the capture rather than to the report channel.
   env.io.write = env.print
   -- `warn` writes to standard error, which is where the records go, so it is a
   -- capture too rather than anything a payload can steer.
   env.warn = function(...) env.print("[warn] ", ...) end
   env._G = env
end

-- ------------------------------------------------------------------- the runner

-- Only a scalar is worth reporting: a table or a function would print as an
-- address, and the sandbox has no way to inspect one safely.
local function reportable(value)
   local kind = type(value)
   if kind == "string" then return text(value):sub(1, 200) end
   if kind == "number" or kind == "boolean" then return tostring(value) end
   return nil
end

-- The order of this ladder is the order of how much a verdict overstates.
-- `exec` first, because reaching an execution sink is the only thing here that
-- means code ran. `process` second, so a payload that ended the process without
-- executing anything is reported as an escape rather than as an execution. A
-- limit stop third, so a payload the sandbox had to interrupt is not described by
-- the sink it happened to reach on its way out.
local function decide(failed)
   for _, sink in ipairs(sinks) do
      if sink.kind == "exec" then return "rce" end
   end
   for _, sink in ipairs(sinks) do
      if sink.kind == "process" then return "escape" end
   end
   if stop_reason then return "timeout" end
   if #sinks > 0 then return "partial" end
   return failed and "error" or "benign"
end

-- One verdict table, built from the module state, so a payload that never got as
-- far as running reports the same shape as one that did. `failed` says whether
-- the payload's own chunk raised; the reason and its source are decided here so
-- that a limit that fired always reads as ours, and a payload's own error message
-- always reads as its.
local function build_verdict(failed, reason, result)
   return {
      verdict = decide(failed),
      reason = reason,
      reason_source = (stop_reason or not failed) and "sandbox" or "payload",
      result = result,
      output = table.concat(output),
      instructions = spent,
      elapsed_ms = math.floor((real_os.clock() - started) * 1000),
      sinks = sinks,
      chain = chain,
      escapes = escapes,
   }
end

function __luasec_sandbox(payload, options)
   limits = options
   started = real_os.clock()
   nonce = tostring(__LUASEC_NONCE or "")
   source_name = (type(options.source) == "string" and options.source ~= "") and options.source
      or DEFAULT_SOURCE

   -- A verdict describes the Lua that produced it. Running the payload under a
   -- dialect the sandbox was not written for would report an outcome nobody
   -- should rely on, so the payload does not run at all.
   if not SUPPORTED_DIALECTS[_VERSION] then
      return {verdict = "error",
              reason = "the payload validator supports Lua 5.3 and 5.4, and this interpreter is "
               .. tostring(_VERSION)}
   end

   build_env()

   -- The screen runs in front of this compile too, which is why it is here rather
   -- than only inside `load`: the payload the driver pasted in is exactly the
   -- chunk most likely to be a doubling loop, and `pcall` around `real_load` is
   -- what keeps the limit sentinel from escaping into the generated program and
   -- taking the child with it before a verdict is emitted. It fails in exactly one
   -- way - by raising LIMIT, a local upvalue the payload cannot name - so the
   -- reason is ours to report and not a string to be guessed at.
   local screened, screen_error = real_pcall(screen, payload)
   if not screened then
      return build_verdict(true, stop_reason or tostring(screen_error))
   end

   local chunk, compile_error = real_load(payload, "@" .. source_name, "t", env) -- luasec: ignore 703  real_load is load; compiling the payload is what is being validated
   if not chunk then
      return {verdict = "error", reason = "payload could not be compiled: " .. tostring(compile_error)}
   end

   real_debug.sethook(hook, "", INSTRUCTIONS_PER_TICK)
   local packed = table.pack(real_pcall(chunk))
   real_debug.sethook()

   return build_verdict(not packed[1],
      stop_reason or (packed[1] and "payload completed" or tostring(packed[2])),
      reportable(packed[2]))
end

function __luasec_emit(verdict)
   record("__LUASEC_REPORT__", {
      blob(verdict.verdict or "error"),
      blob(verdict.reason or "no reason reported"),
      blob(verdict.result or ""),
      string.format("%d", verdict.instructions or 0),
      string.format("%d", verdict.elapsed_ms or 0),
      blob(verdict.reason_source or "sandbox"),
      blob(_VERSION),
      blob(source_name),
   })
   for _, sink in ipairs(verdict.sinks or {}) do
      record("__LUASEC_SINK__", {
         blob(sink.name),
         string.format("%d", sink.line or 0),
         blob(sink.source or source_name),
         blob(sink.kind or "probe"),
         blob(sink.arg or ""),
      })
   end
   for _, name in ipairs(verdict.chain or {}) do
      record("__LUASEC_CHAIN__", {blob(name)})
   end
   for _, escape in ipairs(verdict.escapes or {}) do
      record("__LUASEC_ESCAPE__", {blob(escape.name), string.format("%d", escape.line or 0)})
   end
   -- One record per printed line, so the payload's own newlines do not have to be
   -- escaped and the parent can hand back a string a caller can split.
   local printed = (verdict.output or ""):gsub("\n$", "")
   if printed ~= "" then
      for line in (printed .. "\n"):gmatch("([^\n]*)\n") do
         record("__LUASEC_OUTPUT__", {blob(line)})
      end
   end
   -- Every record has been written by now, and a child the watchdog kills
   -- mid-emit would lose the tail of the verdict, so nothing is left buffered.
   RECORD:flush()
end
