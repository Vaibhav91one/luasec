-- Fixture: a staged loader whose blob is decoded through a substitution
-- function and handed to `load`. This is the shape issue #266 is decided on:
-- whatever is changed to quiet the build tool in `source_rewrite.lua`, this one
-- has to keep firing, or the rule was deleted rather than corrected.
local blob = "4c4a02021b4c4a024b5c64656c7461782800"

local function stage(hex)
   return (hex:gsub("%x%x", function(pair)
      return string.char(tonumber(pair, 16))
   end))
end

local payload = stage(blob)
local f = assert(load(payload, "=stage"))

return f
