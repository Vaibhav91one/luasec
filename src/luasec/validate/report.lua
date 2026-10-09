-- Human readable rendering of a payload validation verdict.
--
-- Deliberately not a finding report: a verdict is an outcome, not a list of
-- codes, so there is no severity, no CWE and no exit threshold to apply.
--
-- Every line here is luasec's own except the ones marked `payload|`, and the
-- marking is not decoration. A payload chooses the text of everything it prints,
-- of the value it returns, of the argument it passes to a sink and of the error
-- message it raises, so all of it lands in a report an operator is about to
-- paste into a ticket. It is rendered inside a fixed-width gutter, with control
-- bytes escaped, so no byte of it can be read as a field of this report.
local validate_report = {}

-- Untrusted text, rendered so it cannot be mistaken for the tool's own. Control
-- bytes become escapes: a payload cannot move the cursor, clear a line, or put a
-- newline into a line the report is counting.
local payload_text = require("luasec.util.util").sanitize

local function payload_block(label, value)
   local lines = {"  " .. label}
   for line in (tostring(value) .. "\n"):gmatch("([^\n]*)\n") do
      lines[#lines + 1] = "    payload| " .. payload_text(line)
   end
   return lines
end

function validate_report.render(verdict, name)
   local lines = {"luasec: validation of " .. (name or verdict.source or "<source>")}

   lines[#lines + 1] = "  verdict:   " .. tostring(verdict.verdict)
   -- An exit reason that is the payload's own error message is its text, not
   -- ours, and says so.
   if verdict.reason_source == "payload" then
      lines[#lines + 1] = "  exit:      [payload text] " .. payload_text(verdict.exit_reason or "")
   else
      lines[#lines + 1] = "  exit:      " .. tostring(verdict.exit_reason)
   end

   if #(verdict.sinks_reached or {}) > 0 then
      lines[#lines + 1] = "  reached:"
      for _, sink in ipairs(verdict.sinks_reached) do
         lines[#lines + 1] = string.format("    %s [%s] at %s:%d%s",
            sink.name, sink.kind, sink.source or "<source>", sink.line or 0,
            (sink.arg and sink.arg ~= "") and (" with [payload text] " .. payload_text(sink.arg)) or "")
      end
   end

   if #(verdict.escape_attempts or {}) > 0 then
      lines[#lines + 1] = "  escapes:"
      for _, escape in ipairs(verdict.escape_attempts) do
         lines[#lines + 1] = "    " .. escape.name
      end
   end

   if #(verdict.payload_chain or {}) > 0 then
      lines[#lines + 1] = "  chain:     " .. table.concat(verdict.payload_chain, " -> ")
   end

   -- What the payload returned. A number or a string it chose, so it is labelled
   -- the same way its printed output is.
   if verdict.payload_result and verdict.payload_result ~= "" then
      lines[#lines + 1] = "  returned:  [payload text] " .. payload_text(verdict.payload_result)
   end

   -- What the payload printed, including anything it wrote to `io.stdout`,
   -- `io.stderr` or `warn`. Those go through the same capture, because in this
   -- sandbox they are not handles on anything: the report channel is the child's
   -- standard error and the payload is given no member of `io` that reaches it.
   if verdict.payload_output and verdict.payload_output ~= "" then
      for _, line in ipairs(payload_block(
         "payload output (text the snippet produced; not a luasec finding):",
         verdict.payload_output)) do
         lines[#lines + 1] = line
      end
   end

   local duration = string.format("  cpu:       %dms", verdict.duration_ms or 0)
   -- Zero means the payload finished inside one instruction tick, which is worth
   -- saying nothing about rather than reporting as a measurement.
   if verdict.instructions and verdict.instructions > 0 then
      duration = duration .. string.format(", %d instructions", verdict.instructions)
   end
   lines[#lines + 1] = duration
   -- A verdict is about one snippet under one Lua, and both are named so it can
   -- be traced back to the file and reproduced on the interpreter it ran under.
   lines[#lines + 1] = "  lua:       " .. tostring(verdict.lua or "unknown")
      .. " (" .. tostring(verdict.interpreter or "unknown") .. ")"

   return table.concat(lines, "\n")
end

return validate_report
