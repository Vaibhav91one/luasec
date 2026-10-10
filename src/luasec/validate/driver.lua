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
   __LUASEC_RESIDENT__ = true,
   __LUASEC_RSSWATCH__ = true,
}
local KILLED = "__LUASEC_WALLCLOCK__"
local RESIDENT = "__LUASEC_RESIDENT__"
local RSSWATCH = "__LUASEC_RSSWATCH__"

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

-- The resident-set supervisor's own knobs. They are not child limits, so they are
-- resolved here rather than in LIMITS: `rss_limit_kb` is measured in kilobytes of
-- the child's whole address space and has to be derived from the heap ceiling
-- rather than fixed, because an honest payload reaches the heap ceiling plus
-- allocator overhead before the child's own check notices.
--
-- The multiplier is 1.5 because that is above the peak a compliant payload
-- reaches and measured here as 1.33x the heap ceiling (60MB of live parts plus
-- allocator overhead, refused by the check in front of `table.concat`). Below
-- that the supervisor would report a memory exhaustion the payload never caused.
local RSS_MULTIPLIER = 1.5
local RSS_POLL_MS = 1

-- The page size `/proc/<pid>/statm` counts in, expressed in kilobytes. Every
-- architecture Linux runs on with a 64-bit address space has a 4 KiB base page,
-- and the alternative - a `getconf PAGESIZE` fork per validated payload - costs
-- more than the whole probe on the platforms where this path is taken.
local PROC_PAGE_KB = 4

-- How many consecutive empty probes mean this platform has no way to read the
-- child's resident set at all, rather than a child that has just not started.
local RSS_UNAVAILABLE_AFTER = 50

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
-- `escape` is a process-control attempt that executed nothing: a payload that
-- called os.exit is not an execution, and calling it one was the over-strong
-- claim this verdict exists to remove.
local VERDICTS = {rce = true, escape = true, partial = true, benign = true,
                  timeout = true, error = true}

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
            elseif tag == RESIDENT then
               report.rss_kb = tonumber(fields[1])
            elseif tag == RSSWATCH then
               report.rss_watch = fields[1]
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

-- The resident-set supervisor: a third job in the same shell group, alongside
-- the wall-clock watchdog, that watches the child's resident set and kills it
-- when it passes the limit.
--
-- It has to live here rather than inside the child, because nothing inside the
-- child can see this. `..` compiles to one OP_CONCAT, a single C-level call: the
-- instruction hook cannot run inside it and a Lua count hook cannot preempt it,
-- so a loop that doubles a string does its whole work inside one tick window.
-- Measured before this supervisor existed, against a 64MB ceiling: three runs of
-- the doubling payload gave 2876342272, 4297375744 and 4297392128 bytes of peak
-- resident set, 42.9x to 65.6x the ceiling, and the child still reported
-- `timeout` and "memory ceiling exceeded" as though the ceiling had held. The
-- reason that was true is that the ceiling was only ever checked between
-- allocations, and this one is the allocation.
--
-- What the payload can reach here: nothing. The loop's whole text is generated
-- above from constants, the only variable it reads is the pid the shell took
-- from `$!` before the payload existed, and the only channel it has to the
-- parent is the record pipe - where its one line is gated by the same per-run
-- nonce as the child's records, and the payload has no route to that nonce.
--
-- Two things this deliberately does not do. It does not sleep between samples
-- once the child is within half the limit, because on macOS the sample costs a
-- `ps` fork of about 2.9ms and a sleep on top of that would double the window
-- the payload has to overshoot in; measured, the sleep cost 4.05x the ceiling
-- against 2.00x without it, and the spin is paid only by payloads actually
-- holding memory. And it does not pretend the limit is exact: the achievable
-- bound is the limit plus whatever the child can allocate in one sample, so
-- SECURITY.md states the measured peak rather than the configured threshold.
local function resident_watchdog(limits, token)
   local poll = string.format("%.3f", math.max(limits.rss_poll_ms, 0) / 1000)
   return {
      "(",
      string.format("__luasec_close=%d", math.floor(limits.rss_limit_kb / 2)),
      "__luasec_seen=0",
      "while kill -0 $__luasec_child 2>/dev/null; do",
      "__luasec_rss=''",
      -- Linux: statm's second field is resident pages, read by the shell's own
      -- `read`, so a sample costs one file open and no fork at all.
      "if [ -r /proc/$__luasec_child/statm ]; then",
      string.format("read -r __luasec_p _ __luasec_q < /proc/$__luasec_child/statm 2>/dev/null "
         .. "&& __luasec_rss=$((_ * %d))", PROC_PAGE_KB),
      -- Everywhere else: one fork. This is the floor of what is measurable
      -- without a C binding, and it is what sets the overshoot on macOS.
      "else",
      "__luasec_rss=$(ps -o rss= -p $__luasec_child 2>/dev/null)",
      "fi",
      -- `ps` pads its output, so the reading arrives as "  20480". The arithmetic
      -- expansion is a shell builtin that skips the padding, and it is the only
      -- normalisation available: a bracket expression containing a blank is a
      -- syntax error in this /bin/sh (measured, GNU bash 3.2 in POSIX mode), and
      -- the generated script cannot quote a pattern because the printf formats
      -- below already own the single quotes. Without it the record the parent
      -- parses carries a leading blank, the field reads as empty, and a
      -- resident-set kill is silently reported as the wall clock instead.
      "if [ -n \"$__luasec_rss\" ]; then",
      "__luasec_rss=$((__luasec_rss))",
      "__luasec_seen=1",
      "if [ \"$__luasec_rss\" -gt " .. limits.rss_limit_kb .. " ]; then",
      -- Written before the kill, and the parent reads to end of pipe, so the
      -- reason survives a child that never got to report a verdict of its own.
      "printf '" .. RESIDENT .. " " .. token .. " %d\\n' $__luasec_rss",
      "kill -9 $__luasec_child 2>/dev/null",
      "exit 0",
      "fi",
      "if [ \"$__luasec_rss\" -le $__luasec_close ]; then",
      -- A `sleep` that cannot take a fraction would spin here. Better to say so
      -- than to leave the payload with no resident-set bound and no word about
      -- it: the parent turns this record into the verdict's exit reason.
      "sleep " .. poll .. " 2>/dev/null || { printf '" .. RSSWATCH .. " " .. token
         .. " %d:cannot sleep for a fraction of a second\\n' " .. limits.rss_poll_ms
         .. "; exit 0; }",
      "fi",
      "else",
      -- No reading. That is a child that has not started, a child that has become
      -- a zombie (`ps` reports nothing for one, measured), or a platform with no
      -- way to report a resident set at all. Only the last is worth a word, and
      -- only a platform that has never answered once can be that - which is what
      -- `__luasec_seen` distinguishes, so that a payload which dies at the moment
      -- it is first sampled is not reported as a platform that cannot be measured.
      "if [ $__luasec_seen -eq 0 ]; then",
      "__luasec_quiet=$((__luasec_quiet + 1))",
      "if [ $__luasec_quiet -ge " .. RSS_UNAVAILABLE_AFTER .. " ]; then",
      "printf '" .. RSSWATCH .. " " .. token
         .. " %d:no way to read a process resident set on this platform\\n' 0",
      "exit 0",
      "fi",
      "fi",
      "sleep " .. poll .. " 2>/dev/null || { printf '" .. RSSWATCH .. " " .. token
         .. " %d:cannot sleep for a fraction of a second\\n' " .. limits.rss_poll_ms
         .. "; exit 0; }",
      "fi",
      "done",
      ") &",
      "__luasec_resident=$!",
   }
end

-- The one place lua-doctor spawns a process, and the reason it has to: a payload
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
-- where no check can run. The resident-set supervisor's sleep is fractional on
-- purpose, because it is a sampling interval rather than a deadline, and it is
-- written as a fixed-point literal so it can never come out as `1e-07`.
local function capture(interpreter, program, limits, token)
   local watchdog_seconds = math.ceil(limits.timeout_ms / 1000)
   local lines = {
      -- Two bounds the kernel may enforce, independent of anything the child or
      -- the watchdog can be talked out of. `ulimit -v` is refused outright on
      -- macOS - measured: "ulimit: virtual memory: cannot modify limit: Invalid
      -- argument" - so it is a backstop on the platforms that honour it and
      -- nowhere else, and the resident-set supervisor is the bound everywhere.
      -- The CPU limit is honoured on macOS (measured: the child dies of SIGXCPU)
      -- and gets a second of headroom so the child normally reports the stop
      -- itself, with a clearer reason, before the kernel steps in.
      "ulimit -v " .. (limits.max_memory_kb + 65536) .. " 2>/dev/null || true",
      "ulimit -t " .. (math.floor(limits.timeout_ms / 1000) + 1) .. " 2>/dev/null || true",
      shell_quote(interpreter) .. " -e " .. shell_quote(program) .. " 2>&1 1>/dev/null &",
      "__luasec_child=$!",
      "( sleep " .. watchdog_seconds .. "; kill -9 $__luasec_child 2>/dev/null ) >/dev/null 2>&1 &",
      "__luasec_watchdog=$!",
   }
   for _, line in ipairs(resident_watchdog(limits, token)) do
      lines[#lines + 1] = line
   end
   for _, line in ipairs({
      "wait $__luasec_child",
      "__luasec_status=$?",
      -- Both jobs are killed before the group exits, which is also what closes
      -- the record pipe: the parent blocks until every writer is gone, so a
      -- surviving watchdog would hang the caller rather than leak.
      "kill -9 $__luasec_watchdog 2>/dev/null",
      "kill -9 $__luasec_resident 2>/dev/null",
      -- A child one of the watchers or the kernel killed never got to answer.
      -- 137 is SIGKILL, 152 is SIGXCPU from `ulimit -t`; say which, because
      -- otherwise a child that ran out of time is indistinguishable from one that
      -- crashed. The resident-set kill arrives as its own record before this one,
      -- and the parent prefers it, because both end in SIGKILL. The nonce is the
      -- parent's, so this line is a record like any other.
      "case $__luasec_status in 137|152) printf '" .. KILLED .. " " .. token .. " %d\\n' $__luasec_status;; esac",
      "exit $__luasec_status",
   }) do
      lines[#lines + 1] = line
   end

   local command = "(\n" .. table.concat(lines, "\n") .. "\n) 2>/dev/null"
   -- lua-doctor: ignore 702  the command is built from quoted, sandboxed fragments, not from request data
   -- lua-doctor: ignore 712  the same command: a partly quoted flow whose "file read" sources are
   -- lua-doctor's own child.lua and the random nonce it reads from /dev/urandom
   -- lua-doctor: ignore 709  same, and for the same reason. #281 made this visible:
   -- the two things that reach `command` are `child_source()` reading lua-doctor's
   -- own child.lua, and `opts.lua or os.getenv("LUA_DOCTOR_LUA") or os.getenv(
   -- "LUA_BIN")` -- the interpreter path, which the operator running lua-doctor
   -- chooses. Neither is request data, and both are single-quoted by `quote`.
   -- Reported rather than fixed here: a 709 through a fragment lua-doctor itself
   -- quotes looks like a sanitizer the rule does not credit, which is its own
   -- question and not this commit's to answer.
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

   -- The resident-set supervisor's own two settings. `rss_limit_kb` is the
   -- threshold it kills the child at, and defaults to a multiple of the child's
   -- heap ceiling because those measure different things: the ceiling is Lua
   -- bytes and the threshold is the process. Both are configurable, and
   -- `rss_poll_ms` is the sampling gap while the child is small; see
   -- `resident_watchdog` for why it stops sleeping near the limit.
   local multiplier = tonumber(opts.rss_multiplier)
   if not multiplier or multiplier ~= multiplier or multiplier <= 0 then
      multiplier = RSS_MULTIPLIER
   end
   local rss_limit = whole_number(opts.rss_limit_kb,
      {default = math.floor(limits.max_memory_kb * multiplier + 0.5),
       low = 1024, high = 1 << 30})
   limits.rss_limit_kb = rss_limit
   limits.rss_poll_ms = whole_number(opts.rss_poll_ms,
      {default = RSS_POLL_MS, low = 0, high = 60000})

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
      and opts.name or "lua-doctor-payload"

   -- `lua -e` treats an option argument that starts with "-" as another option
   -- and reports "needs argument", and child.lua opens with a comment, so the
   -- program gets a leading newline to keep its first argument parseable.
   local token = nonce()
   local program = "\n-- lua-doctor validator child\n" .. child_source()
      .. "\n__LUASEC_NONCE = " .. string.format("%q", token)
      .. "\n__LUASEC_PAYLOAD = " .. long_string(source)
      .. "\n__LUASEC_LIMITS = "
      .. string.format(
         "{timeout_ms=%d, max_instructions=%d, max_memory_kb=%d, max_load_depth=%d,"
         .. " max_source_bytes=%d, source=%q}",
         limits.timeout_ms, limits.max_instructions, limits.max_memory_kb,
         limits.max_load_depth, limits.max_source_bytes, source_name)
      .. "\n" .. ENTRY

   -- The interpreter is the one the analyzer is running under, not whatever
   -- `lua` happens to be on PATH: a verdict describes the Lua that produced it,
   -- and bin/lua-doctor exports this so the two are the same build. The child checks
   -- the dialect for itself and refuses the payload under one it does not
   -- support, and the version it ran under comes back in the verdict.
   local interpreter = opts.lua or os.getenv("LUA_DOCTOR_LUA") or os.getenv("LUA_BIN") or "lua"

   local started = os.clock()
   local output = capture(interpreter, program, limits, token)
   local elapsed = math.floor((os.clock() - started) * 1000)

   local report = collect(output, token)
   report.interpreter = interpreter

   -- The child never got to answer, so a bound stopped it and one of the
   -- watchers says which. The resident-set kill is checked first because it also
   -- ends in SIGKILL, so both watchers can have a record to offer and only one of
   -- them is why the run ended. Anything else that left no report is a harness
   -- failure, not a verdict.
   if report.verdict == "error" and report.exit_reason:find("no verdict", 1, true) then
      if report.rss_kb then
         report.verdict = "timeout"
         report.exit_reason = string.format(
            "resident set of %dkB exceeded the %dkB limit; the validator child was killed",
            report.rss_kb, limits.rss_limit_kb)
      elseif report.rss_watch then
         report.exit_reason = "no resident-set bound could be installed on this platform: "
            .. report.rss_watch
      elseif report.killed then
         report.verdict = "timeout"
         report.exit_reason = string.format("wall clock of %dms exceeded; the validator child was killed",
            limits.timeout_ms)
      else
         report.exit_reason = "the validator child failed before reporting; "
            .. "check that the interpreter exists and can run a chunk"
      end
   end
   report.killed = nil
   report.rss_watch = nil
   -- The threshold travels with the verdict whether or not it fired, so a reader
   -- can tell a memory stop the child reported from one the parent imposed.
   report.rss_limit_kb = limits.rss_limit_kb
   report.rss_poll_ms = limits.rss_poll_ms

   -- `duration_ms` is the CPU time the payload burned inside the child, which is
   -- the only clock both processes can agree on; the wall clock is bounded
   -- separately by `timeout_ms` and reported when it fires. The parent's own
   -- reading is the fallback for a child that never answered.
   report.duration_ms = report.duration_ms or elapsed
   return report
end

return driver
