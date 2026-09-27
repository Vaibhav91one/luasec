-- Human readable rendering of a payload validation verdict.
--
-- Deliberately not a finding report: a verdict is an outcome, not a list of
-- codes, so there is no severity, no CWE and no exit threshold to apply.
local validate_report = {}

function validate_report.render(verdict, name)
   local lines = {"luasec: validation of " .. (name or "<source>")}

   lines[#lines + 1] = "  verdict:   " .. tostring(verdict.verdict)
   lines[#lines + 1] = "  exit:      " .. tostring(verdict.exit_reason)

   if #(verdict.sinks_reached or {}) > 0 then
      lines[#lines + 1] = "  reached:"
      for _, sink in ipairs(verdict.sinks_reached) do
         lines[#lines + 1] = string.format("    %s [%s] at %s:%d%s",
            sink.name, sink.kind, sink.source or "<source>", sink.line or 0,
            (sink.arg and sink.arg ~= "") and (" with " .. sink.arg) or "")
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

   if verdict.result and verdict.result ~= "" then
      lines[#lines + 1] = "  result:    " .. verdict.result
   end

   -- What the payload printed, kept out of the tool's own output so a payload
   -- cannot put words in the report or forge a finding in someone's log.
   if verdict.output and verdict.output ~= "" then
      lines[#lines + 1] = "  printed:"
      for line in (verdict.output .. "\n"):gmatch("([^\n]*)\n") do
         lines[#lines + 1] = "    | " .. line
      end
   end

   local duration = string.format("  cpu:       %dms", verdict.duration_ms or 0)
   -- Zero means the payload finished inside one instruction tick, which is worth
   -- saying nothing about rather than reporting as a measurement.
   if verdict.instructions and verdict.instructions > 0 then
      duration = duration .. string.format(", %d instructions", verdict.instructions)
   end
   lines[#lines + 1] = duration

   return table.concat(lines, "\n")
end

return validate_report
