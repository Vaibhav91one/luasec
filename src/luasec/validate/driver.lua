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

-- The records the child sends, and the line the shell prints when it, or the
-- kernel, killed the child.
local MARKERS = {
   __LUASEC_REPORT__ = true,
   __LUASEC_SINK__ = true,
   __LUASEC_CHAIN__ = true,
   __LUASEC_ESCAPE__ = true,
   __LUASEC_OUTPUT__ = true,
   __LUASEC_WALLCLOCK__ = true,
}
local KILLED = "__LUASEC_WALLCLOCK__"

-- Every limit arrives in the child as a literal in the program text, so a value
-- with a fractional part would raise inside `string.format("%d", ...)` instead of
-- being rounded - and a value of zero would leave the watchdog with nothing to
-- sleep for. `whole_number` normalises both, and clamps a caller who asks for
-- more than any machine should honour.
local LIMITS = {
   {key = "timeout_ms", default = 2000, low = 1, high = 3600000},
   {key = "max_instructions", default = 5000000, low = 100, high = 1e15},
   {key = "max_memory_kb", default = 65536, low = 1024, high = 1 << 30},
   {key = "max_load_depth", default = 32, low = 1, high = 1000},
   {key = "max_source_bytes", default = 262144, low = 1, high = 1 << 24},
}

local function whole_number(value, spec)
   local number = tonumber(value)
   if not number or number ~= number or number <= -math.huge or number >= math.huge then
      number = spec.default
   end
   number = math.floor(number + 0.5)
   if number < spec.low then number = spec.low end
   if number > spec.high then number = spec.high end
   return number
end

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

-- Read the fields that follow the tag and nonce. A field that is not followed by
-- a space, or is followed by anything else, means the line is not a record.
local function read_fields(line, from)
   local fields = {}
   local pos = from or 1
   while pos <= #line do
      local value, next_pos = read_field(line, pos)
      fields[#fields + 1] = value
      if next_pos > #line then break end
      if line:sub(next_pos, next_pos) ~= " " then return nil end
      pos = next_pos + 1
   end
   return fields
end

-- A per-run token for the record channel. The child stamps it on every record
-- and only the child is given it, so a line that arrives without it is not a
-- record: it is the shell talking, a Lua warning, or a payload that reached the
-- channel by some other route. All three are dropped, which is what makes the
-- records unforgeable rather than merely hard to forge.
local function nonce()
   local handle = io.open("/dev/urandom", "rb")
   if handle then
      local bytes = handle:read(16)
      handle:close()
      if bytes and #bytes == 16 then
         return (bytes:gsub(".", function(char) return string.format("%02x", char:byte()) end))
      end
   end
   -- No entropy device. A weaker token still separates our records from a
   -- payload's, because the payload has no route to it at all.
   math.randomseed(os.time() + math.floor(os.clock() * 1e6))
   return string.format("%016x%016x", math.random(0, 2 ^ 31 - 1), math.random(0, 2 ^ 31 - 1))
end

-- The verdicts this version knows. A record can only come from the child, and the
-- child only ever writes one of these, but a verdict is the one field everything
-- downstream trusts, so an unrecognised one is an error rather than a pass.
local VERDICTS = {rce = true, partial = true, benign = true, timeout = true, error = true}

-- The child sends one record per line, and each one is `<tag> <nonce> <fields>`.
local function collect(output, token)
   local report = {verdict = "error", exit_reason = "the validator child produced no verdict",
                   sinks_reached = {}, payload_chain = {}, escape_attempts = {}, printed = {},
                   killed = nil}

   for line in tostring(output):gmatch("[^\n]+") do
      local tag, echoed = line:match("^(%S+) (%S+) ")
      if tag and echoed == token and MARKERS[tag] then
         local fields = read_fields(line, #tag + #echoed + 3)
         if fields then
            if tag == "__LUASEC_REPORT__" then
               if VERDICTS[fields[1]] then
                  report.verdict = fields[1]
                  report.exit_reason = fields[2]
               else
                  report.exit_reason = "the validator child reported a verdict this version does not know: "
                     .. tostring(fields[1])
               end
               report.payload_result = fields[3]
               report.instructions = tonumber(fields[4])
               report.duration_ms = tonumber(fields[5])
               report.reason_source = fields[6]
               report.lua = fields[7]
               report.source = fields[8]
               report.payload_result = fields[3]
               report.instructions = tonumber(fields[4])
               report.duration_ms = tonumber(fields[5])
               report.reason_source = fields[6]
               report.lua = fields[7]
               report.source = fields[8]
            elseif tag == "__LUASEC_SINK__" then
               report.sinks_reached[#report.sinks_reached + 1] =
                  {name = fields[1], line = tonumber(fields[2]), source = fields[3],
                   kind = fields[4], arg = fields[5]}
            elseif tag == "__LUASEC_CHAIN__" then
               report.payload_chain[#report.payload_chain + 1] = fields[1]
            elseif tag == "__LUASEC_ESCAPE__" then
               report.escape_attempts[#report.escape_attempts + 1] =
                  {name = fields[1], line = tonumber(fields[2])}
            elseif tag == "__LUASEC_OUTPUT__" then
               report.printed[#report.printed + 1] = fields[1]
            elseif tag == "__LUASEC_WALLCLOCK__" then
               report.killed = tonumber(fields[1])
            end
         end
      end
   end

   if #report.printed > 0 then report.payload_output = table.concat(report.printed, "\n") end
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
-- The two streams are pointed at different places on purpose:
--
--   * the child's standard error is the record channel, and it is the pipe the
--     parent reads. Records go there.
--   * the child's standard output is /dev/null, so even a real handle on stdout
--     could not put a byte in the channel the parent parses. The redirections are
--     in that order on purpose: `2>&1` first sends stderr to the pipe the
--     command inherited, then `1>/dev/null` moves stdout out of the way.
--   * the shell group's own stderr is /dev/null, because the shell narrates a
--     killed background job to its own stderr, printing the whole command line.
--
-- The watchdog's sleep is a whole number of seconds, rounded up. `sleep` is fed
-- the value as text, and a fractional second formats as something like 1e-07 -
-- which `sleep` reads as a rounding error and returns immediately, leaving the
-- payload with no wall clock at all, or reads as ten million seconds. A whole
-- second is the only value every `sleep` agrees on; the deadline it guards stays
-- the child's own per-tick check, and this is the backstop for a payload wedged
-- where no check can run.
local function capture(interpreter, program, limits, token)
   local watchdog_seconds = math.ceil(limits.timeout_ms / 1000)
   local command = "(\n" .. table.concat({
      -- Two bounds the kernel may enforce, independent of anything the child or
      -- the watchdog can be talked out of. `ulimit -v` is refused outright on
      -- macOS - measured: "ulimit: virtual memory: cannot modify limit: Invalid
      -- argument" - so the memory ceiling lives in the child, where it is
      -- checked, and this is only a backstop where a platform honours it. The
      -- CPU limit is honoured on macOS (measured: the child dies of SIGXCPU) and
      -- gets a second of headroom so the child normally reports the stop itself,
      -- with a clearer reason, before the kernel steps in.
      "ulimit -v " .. (limits.max_memory_kb + 65536) .. " 2>/dev/null || true",
      "ulimit -t " .. (math.floor(limits.timeout_ms / 1000) + 1) .. " 2>/dev/null || true",
      shell_quote(interpreter) .. " -e " .. shell_quote(program) .. " 2>&1 1>/dev/null &",
      "__luasec_child=$!",
      "( sleep " .. watchdog_seconds .. "; kill -9 $__luasec_child 2>/dev/null ) >/dev/null 2>&1 &",
      "__luasec_watchdog=$!",
      "wait $__luasec_child",
      "__luasec_status=$?",
      "kill -9 $__luasec_watchdog 2>/dev/null",
      -- A child the watchdog or the kernel killed never got to answer. 137 is
      -- SIGKILL, 152 is SIGXCPU from `ulimit -t`; say which, because otherwise a
      -- child that ran out of time is indistinguishable from one that crashed.
      -- The nonce is the parent's, so this line is a record like any other.
      "case $__luasec_status in 137|152) printf '" .. KILLED .. " " .. token .. " %d\\n' $__luasec_status;; esac",
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
   for _, spec in ipairs(LIMITS) do
      limits[spec.key] = whole_number(opts[spec.key], spec)
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

   -- The name the verdict is traced back to. It becomes the payload's chunk name,
   -- which is what every reported line number is counted in, so a verdict without
   -- it points at nothing an operator can go and look at.
   local source_name = (type(opts.name) == "string" and opts.name ~= "")
      and opts.name or "luasec-payload"

   -- `lua -e` treats an option argument that starts with "-" as another option
   -- and reports "needs argument", and child.lua opens with a comment, so the
   -- program gets a leading newline to keep its first argument parseable.
   local token = nonce()
   local program = "\n-- luasec validator child\n" .. child_source()
      .. "\n__LUASEC_NONCE = " .. string.format("%q", token)
      .. "\n__LUASEC_PAYLOAD = " .. long_string(source)
      .. "\n__LUASEC_LIMITS = "
      .. string.format("{timeout_ms=%d, max_instructions=%d, max_memory_kb=%d, max_load_depth=%d, source=%q}",
           limits.timeout_ms, limits.max_instructions, limits.max_memory_kb,
           limits.max_load_depth, source_name)
      .. "\n" .. ENTRY

   -- The interpreter is the one the analyzer is running under, not whatever
   -- `lua` happens to be on PATH: a verdict describes the Lua that produced it,
   -- and bin/luasec exports this so the two are the same build. The child checks
   -- the dialect for itself and refuses the payload under one it does not
   -- support, and the version it ran under comes back in the verdict.
   local interpreter = opts.lua or os.getenv("LUASEC_LUA") or os.getenv("LUA_BIN") or "lua"

   local started = os.clock()
   local output = capture(interpreter, program, limits, token)
   local elapsed = math.floor((os.clock() - started) * 1000)

   local report = collect(output, token)
   report.interpreter = interpreter

   -- The child never got to answer, so the shell tells us a bound stopped it.
   -- Anything else that left no report is a harness failure, not a verdict.
   if report.verdict == "error" and report.exit_reason:find("no verdict", 1, true) then
      if report.killed then
         report.verdict = "timeout"
         report.exit_reason = string.format("wall clock of %dms exceeded; the validator child was killed",
            limits.timeout_ms)
      else
         report.exit_reason = "the validator child failed before reporting; "
            .. "check that the interpreter exists and can run a chunk"
      end
   end
   report.killed = nil

   -- `duration_ms` is the CPU time the payload burned inside the child, which is
   -- the only clock both processes can agree on; the wall clock is bounded
   -- separately by `timeout_ms` and reported when it fires. The parent's own
   -- reading is the fallback for a child that never answered.
   report.duration_ms = report.duration_ms or elapsed
   return report
end

return driver
