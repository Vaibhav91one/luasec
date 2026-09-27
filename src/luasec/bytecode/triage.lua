-- Turn the bytes of a precompiled chunk into findings.
--
-- Deliberately shallow. We identify the flavor, read the header defensively,
-- and report the execution sinks the constant table names. We do not
-- decompile, so every chunk carries an 801: the source is not available to
-- analyze, whatever else we can say.
--
-- Nothing here raises. A chunk we cannot describe is reported as such, because
-- a scanner that dies on a malformed file is a scanner that can be used to stop
-- one.
local detect = require "luasec.bytecode.detect"
local header = require "luasec.bytecode.header"
local protos = require "luasec.bytecode.protos"
local platform_api = require "luasec.registry.platform_api"

local codes = require "luasec.rules.codes"

local triage = {}

-- A bytecode file has no source lines to point at, so every finding here sits
-- at the top of the file and says so through `location`.
local function finding(code, fields)
   local spec = codes.get(code)
   local result = {
      code = code,
      line = 1,
      column = 1,
      end_column = 1,
      severity = spec.severity,
      confidence = spec.confidence or "medium",
      cwe = spec.cwe,
   }
   for key, value in pairs(fields or {}) do result[key] = value end
   result.message = codes.render(spec, result)
   return result
end

--- The sink names a chunk's constant table refers to.
--
-- A compiled `os.execute(cmd)` stores "os" and "execute" as two separate
-- constants, never the dotted path, so an equality test on one constant would
-- never fire. Two things do survive compilation and both mean the same thing:
--
--   "os.execute"               the whole path, kept as one string constant,
--                              which is what a payload that resolves a sink at
--                              runtime carries
--   "os" then "execute"        the two halves a compiled call leaves behind
--
-- The registry supplies the names, so a platform that declares a new execution
-- sink is picked up without touching this file. Patterns with wildcards are
-- skipped: a constant cannot spell out `io.popen.*`.
local function referenced_sink(constant, next_constant)
   for _, sink in ipairs(platform_api.sinks()) do
      local pattern = sink.pattern
      if not pattern:find("[%*%?]") then
         if pattern == constant then
            return pattern
         end
         local head, tail = pattern:match("^(.-)%.([^%.]+)$")
         if head and next_constant then
            -- Adjacent in either order: `os.execute` and `execute.os` both
            -- compile to the same two constants.
            if (constant == head and next_constant == tail)
               or (constant == tail and next_constant == head)
            then
               return pattern
            end
         end
      end
   end
   return nil
end

--- Sink names referenced by the prototypes in `walked`.
-- Returns a sorted, de-duplicated array, so the report is stable.
function triage.sinks_in(walked)
   local found = {}

   for _, proto in ipairs(walked.protos or {}) do
      local constants = proto.constants or {}
      for index = 1, #constants do
         local constant = constants[index]
         if type(constant) == "string" then
            local next_constant = constants[index + 1]
            if type(next_constant) ~= "string" then next_constant = nil end
            local sink = referenced_sink(constant, next_constant)
            if sink then found[sink] = true end
         end
      end
   end

   local out = {}
   for name in pairs(found) do out[#out + 1] = name end
   table.sort(out)
   return out
end

--- Does the chunk's flavor and version match the interpreter we assume?
function triage.version_matches(parsed, opts)
   opts = opts or {}
   if parsed.flavor ~= header.ASSUMED_FLAVOR then return false end
   local assumed = opts.assume_version or header.ASSUMED_VERSION
   return parsed.version == assumed
end

--- Triage the bytes of a bytecode file. Never raises.
function triage.triage(bytes, opts)
   opts = opts or {}
   local findings = {}

   local id = detect.identify(bytes)
   if not id then return findings end

   local parsed, reason = header.parse(bytes, id)
   if not parsed then
      -- A signature we cannot follow. Not a source parse error, and not a chunk
      -- we can describe either.
      findings[#findings + 1] = finding("805", {
         name = id.version_string,
         reason = reason,
      })
      return findings
   end

   findings[#findings + 1] = finding("801", {
      name = id.version_string,
      flavor = id.flavor,
      version = id.version,
   })

   if not triage.version_matches(parsed, opts) then
      findings[#findings + 1] = finding("803", {
         name = id.version_string,
         assumed_version = opts.assume_version or header.ASSUMED_VERSION,
      })
   end

   local walked, walk_reason = protos.walk(bytes, parsed)

   if walked then
      for _, sink in ipairs(triage.sinks_in(walked)) do
         findings[#findings + 1] = finding("802", {
            name = sink,
            sink = sink,
         })
      end
   end

   if not walked or walked.truncated then
      -- Either the chunk could not be entered at all, or the walk hit one of the
      -- caps. Both mean part of the file is unexplained, which is worth saying.
      findings[#findings + 1] = finding("805", {
         name = (walked and walked.reason) or walk_reason or "prototype walk stopped early",
      })
   end

   return findings
end

return triage
