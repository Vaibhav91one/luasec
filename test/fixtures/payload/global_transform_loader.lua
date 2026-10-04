-- Fixture: luadoc's own template compiler. `translate` is a global function
-- statement this file defines, and it rewrites a template into Lua source by
-- substitution against a pattern. Nothing is decoded, nothing is fetched, and
-- the string was already in hand -- so a loader handed it has not been handed a
-- payload.

local compatmode = false

function translate (s)
   if compatmode then
      s = s:gsub("$|(.-)|%$", "<?lua = %1 ?>")
   end
   return (s:gsub("<%%(.-)%%>", "<?lua %1 ?>"))
end

local function compile (source, chunkname)
   local f, err = loadstring (translate (source), chunkname)
   if not f then error (err, 3) end
   return f
end

return compile