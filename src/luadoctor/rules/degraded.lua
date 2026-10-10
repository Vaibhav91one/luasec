-- The codes that mean a file was not fully analyzed, as opposed to being clean.
--
-- This is the only place that list lives. It used to be written three times -
-- in main.lua for the exit code, in main.lua again for the severity threshold,
-- and in the baseline module - and the copies drifted: the bytecode codes were
-- added to one list and not the other, so a .luac file failed a run with an
-- EMPTY report. Two tables that have to agree are one table.
--
-- A code belongs here when the answer to "did you read this file?" is no:
--   801, 803, 805  the file is bytecode, or is named .lua but will not parse as
--                  source; there is no source to read
--   901, 902       the file could not be read, or was read only by the lexical
--                  scan after the parser rejected it
--   904            the analysis was skipped as too large to run faithfully
--   012            a `-- lua-doctor:` suppression could not be read, so findings may
--                  have been kept or dropped other than the operator asked
--
-- 903 is deliberately NOT here. It reports an API the configured standard does
-- not have - a bitwise operator under `--std luajit` - which is a statement about
-- the profile, not a gap in what was read. Listing it made every tree that uses
-- `<<` fail forever, with no way out.
local M = {}

local DEGRADED = {
   ["012"] = true,
   ["801"] = true,
   ["803"] = true,
   ["805"] = true,
   ["901"] = true,
   ["902"] = true,
   ["904"] = true,
}

--- Is this code a statement that the file was not fully analyzed?
function M.is_degraded(code)
   return DEGRADED[code] == true
end

--- The list, for a caller that has to iterate it.
function M.codes()
   local out = {}
   for code in pairs(DEGRADED) do out[#out + 1] = code end
   table.sort(out)
   return out
end

return M
