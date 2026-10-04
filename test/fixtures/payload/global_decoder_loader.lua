-- Fixture: a global decoder this file defines, handed to the standard
-- loadstring. Resolving the global must not silence it: the chain is real and
-- readable, so the finding is raised on the chain rather than on shape.

function unpack_blob (text)
   local out = {}
   for index = 1, #text do
      out[index] = text:byte(index) - 32
   end
   return string.char(unpack(out))
end

local function run(blob)
   return loadstring(unpack_blob(blob), "=stage")
end

return run