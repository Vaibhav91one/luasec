-- Payload validator: the parent half.
--
-- The payload is untrusted Lua, so it never runs in this process. It is
-- assembled into a one-shot `lua -e` program, handed to a child interpreter, and
-- this process only reads back a verdict. The child is killed if it outlives the
-- wall clock, whatever it happens to be doing.
--
-- The record framing below is implemented twice, here and in child.lua, because
-- the child is deliberately standalone: it cannot require this file, since
-- `require` is one of the capabilities the sandbox removes.

local driver = {}

-- The child announces itself with one of these, once, on the last line it prints.
local MARKER = "__LUASEC_REPORT__"
-- The shell prints this when it, or the kernel, killed the child.
local KILLED = "__LUASEC_WALLCLOCK__"

local LIMITS = {
   timeout_ms = 2000,
   max_instructions = 5000000,
   max_memory_kb = 65536,
   max_load_depth = 32,
   max_source_bytes = 262144,
}

-- Appended to the child program once the payload and the limits are in scope.
local ENTRY = [[
local __luasec_verdict = __luasec_sandbox(__LUASEC_PAYLOAD, __LUASEC_LIMITS)
__luasec_emit(__luasec_verdict)
]]

-- ------------------------------------------------------------------ the wire

-- A field is either a bare integer or "<byte-length>:<the bytes>". Length
-- framing is what keeps a value containing spaces or newlines from being read
-- as a field boundary.
local function read_field(text, pos)
   local digits = text:match("^(%d+):", pos)
   if digits then
      local from = pos + #digits + 1
      return text:sub(from, from + tonumber(digits) - 1), from + tonumber(digits)
   end
   local stop_at = text:find(" ", pos, true)
   if not stop_at then return text:sub(pos), #text + 1 end
   return text:sub(pos, stop_at - 1), stop_at
end

local function read_fields(line)
   local fields, pos = {}, 1
   while pos <= #line do
      if pos > 1 then
         if line:sub(pos, pos) ~= " " then return nil end
         pos = pos + 1
      end
      local value, next_pos = read_field(line, pos)
      fields[#fields + 1] = value
      pos = next_pos
   end
   return fields
end

-- The child prints one record per line. Anything else on the stream is noise:
-- the payload's own writes are recorders, so only a harness failure can add
-- anything, and the last marker line wins.
local function collect(output)
   local report = {verdict = "error", exit_reason = "the validator child produced no verdict",
                   sinks_reached = {}, payload_chain = {}, escape_attempts = {}, printed = {}}

   for line in tostring(output):gmatch("[^\n]+") do
      local fields = read_fields(line)
      if fields then
         if fields[1] == MARKER then
            report.verdict = fields[2]
            report.exit_reason = fields[3]
            report.result = fields[4]
            report.instructions = tonumber(fields[5])
            report.duration_ms = tonumber(fields[6])
         elseif fields[1] == "__LUASEC_SINK__" then
            report.sinks_reached[#report.sinks_reached + 1] =
               {name = fields[2], line = tonumber(fields[3]), source = fields[4],
                kind = fields[5], arg = fields[6]}
         elseif fields[1] == "__LUASEC_CHAIN__" then
            report.payload_chain[#report.payload_chain + 1] = fields[2]
         elseif fields[1] == "__LUASEC_ESCAPE__" then
            report.escape_attempts[#report.escape_attempts + 1] =
               {name = fields[2], line = tonumber(fields[3])}
         elseif fields[1] == "__LUASEC_OUTPUT__" then
            report.printed[#report.printed + 1] = fields[2]
         end
      end
   end

   if #report.printed > 0 then report.output = table.concat(report.printed, "\n") end
   report.printed = nil
   return report
end

-- ------------------------------------------------------------- the child run

-- A long string literal whose bracket level no payload text can close early.
local function long_string(text)
   local level = 0
   while text:find("[" .. string.rep("=", level) .. "[", 1, true) do
      level = level + 1
   end
   local open = "[" .. string.rep("=", level) .. "["
   local close = "]" .. string.rep("=", level) .. "]"
   return open .. "\n" .. text .. "\n" .. close
end

local function child_source()
   local path = debug.getinfo(1, "S").source:gsub("^@", "")
   local handle = assert(io.open(path:gsub("driver%.lua$", "child.lua"), "rb"))
   local text = handle:read("*a")
   handle:close()
   return text
end

-- Single quotes for /bin/sh, with embedded quotes escaped the only safe way.
local function shell_quote(text)
   return "'" .. text:gsub("'", "'\\''") .. "'"
end

-- The one place luasec spawns a process, and the reason it has to: a payload
-- cannot be run in-process, so the sandbox lives in a child. The payload text
-- rides inside a long-bracket literal in the program, so on this command line
-- it is inert data and never shell syntax. The watchdog kills the child at the
-- wall clock, so the parent blocks only until the pipe closes.
--
-- The group runs with stderr on /dev/null because the shell narrates a killed
-- background job to its own stderr, printing the whole command line; the
-- child's stderr is merged into the pipe by the child's own `2>&1`, before the
-- group's redirect applies, so a harness failure still reaches the report.
local function capture(interpreter, program, limits)
   local command = "(\n" .. table.concat({
      -- Two bounds the kernel enforces, independent of anything the child or
      -- the watchdog can be talked out of. `ulimit -v` is not honoured on every
      -- platform, hence the memory ceiling also lives in the child's hook; the
      -- CPU limit gets a second of headroom so the child normally reports the
      -- stop itself, with a clearer reason, before the kernel steps in.
      "ulimit -v " .. (limits.max_memory_kb + 65536) .. " 2>/dev/null || true",
      "ulimit -t " .. (math.floor(limits.timeout_ms / 1000) + 1) .. " 2>/dev/null || true",
      shell_quote(interpreter) .. " -e " .. shell_quote(program) .. " 2>&1 &",
      "__luasec_child=$!",
      "( sleep " .. (limits.timeout_ms / 1000) .. "; kill -9 $__luasec_child 2>/dev/null ) >/dev/null 2>&1 &",
      "__luasec_watchdog=$!",
      "wait $__luasec_child",
      "__luasec_status=$?",
      "kill -9 $__luasec_watchdog 2>/dev/null",
      -- A child the watchdog or the kernel killed never got to answer. 137 is
      -- SIGKILL, 152 is SIGXCPU from `ulimit -t`; say which, because otherwise a
      -- child that ran out of time is indistinguishable from one that crashed.
      "case $__luasec_status in 137|152) printf '" .. KILLED .. " %d\\n' $__luasec_status;; esac",
      "exit $__luasec_status",
   }, "\n") .. "\n) 2>/dev/null"

   local pipe = io.popen(command, "r")
   if not pipe then return "" end
   local output = pipe:read("*a")
   pipe:close()
   return output or ""
end

--- Run `source` in a child interpreter and report what it reached.
-- Returns the verdict table.
function driver.run(source, opts)
   local limits = {}
   for key, fallback in pairs(LIMITS) do
      limits[key] = tonumber(opts[key]) or fallback
   end

   -- A verdict that never got as far as a child, which is a failure of the
   -- request rather than of the payload.
   local function refuse(reason)
      return {verdict = "error", exit_reason = reason,
              sinks_reached = {}, payload_chain = {}, escape_attempts = {}}
   end

   if type(source) ~= "string" or source == "" then
      return refuse("no payload to validate")
   end

   if #source > limits.max_source_bytes then
      return refuse(string.format("payload is larger than the %d byte limit", limits.max_source_bytes))
   end

   -- A NUL byte would truncate the child's command line; the payload could not
   -- be delivered intact, so refuse rather than validate something else.
   if source:find("%z") then
      return refuse("payload contains a NUL byte")
   end

   -- `lua -e` treats an option argument that starts with "-" as another option
   -- and reports "needs argument", and child.lua opens with a comment, so the
   -- program gets a leading newline to keep its first argument parseable.
   local program = "\n-- luasec validator child\n" .. child_source()
      .. "\n__LUASEC_PAYLOAD = " .. long_string(source)
      .. "\n__LUASEC_LIMITS = "
      .. string.format("{timeout_ms=%d, max_instructions=%d, max_memory_kb=%d, max_load_depth=%d}",
           limits.timeout_ms, limits.max_instructions, limits.max_memory_kb, limits.max_load_depth)
      .. "\n" .. ENTRY

   local started = os.clock()
   local output = capture(opts.lua or os.getenv("LUA_BIN") or "lua", program, limits)
   local elapsed = math.floor((os.clock() - started) * 1000)

   local report = collect(output)

   -- The child never got to answer, so the shell tells us a bound stopped it.
   -- Anything else that left no report is a harness failure, not a verdict.
   if report.verdict == "error" and report.exit_reason:find("no verdict", 1, true) then
      local killed = output:match(KILLED .. " (%d+)")
      if killed then
         report.verdict = "timeout"
         report.exit_reason = string.format("wall clock of %dms exceeded; the validator child was killed",
            limits.timeout_ms)
      else
         report.exit_reason = "the validator child failed before reporting; "
            .. "check that the interpreter exists and can run a chunk"
      end
   end

   -- `duration_ms` is the CPU time the payload burned inside the child, which is
   -- the only clock both processes can agree on; the wall clock is bounded
   -- separately by `timeout_ms` and reported when it fires. The parent's own
   -- reading is the fallback for a child that never answered.
   report.duration_ms = report.duration_ms or elapsed
   return report
end

return driver
