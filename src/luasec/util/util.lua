-- Small shared helpers. No luacheck internals, no side effects.
local util = {}

function util.tconcat(list, sep)
   return table.concat(list, sep or "")
end

function util.sorted_keys(t)
   local keys = {}
   for k in pairs(t) do keys[#keys + 1] = k end
   table.sort(keys)
   return keys
end

-- Shallow "is this table an array" check.
function util.is_array(t)
   if type(t) ~= "table" then return false end
   local n = 0
   for k in pairs(t) do
      if type(k) ~= "number" then return false end
      n = n + 1
   end
   return n == #t
end

function util.copy(t)
   local res = {}
   for k, v in pairs(t) do res[k] = v end
   return res
end

function util.deep_merge_into(target, source)
   for k, v in pairs(source) do
      if type(v) == "table" and type(target[k]) == "table" then
         util.deep_merge_into(target[k], v)
      else
         target[k] = v
      end
   end
   return target
end

-- Wildcard match supporting "*" (any run) and "?" (one char), anchored.
-- Used for API path patterns such as "nixio.process.*".
function util.wild_match(pattern, s)
   local p, j = 1, 1
   local plen, slen = #pattern, #s
   local star_p, star_j

   while j <= slen do
      local c = pattern:sub(p, p)
      if c == "*" then
         star_p, star_j = p, j
         p = p + 1
      elseif c == "?" or (c ~= "" and c == s:sub(j, j)) then
         p, j = p + 1, j + 1
      elseif star_p then
         p = star_p + 1
         j = star_j + 1
         star_j = j
      else
         return false
      end
   end

   while p <= plen and pattern:sub(p, p) == "*" do p = p + 1 end
   return p > plen
end

-- Shannon entropy of a string, in bits per byte. Used to spot obfuscated data.
function util.entropy(s)
   if #s == 0 then return 0 end
   local counts = {}
   for i = 1, #s do
      local b = s:sub(i, i)
      counts[b] = (counts[b] or 0) + 1
   end
   local total, e = #s, 0
   for _, n in pairs(counts) do
      local p = n / total
      e = e - p * math.log(p, 2)
   end
   return e
end

function util.is_bas64(s)
   if #s < 16 or #s % 4 ~= 0 then return false end
   return s:match("^[A-Za-z0-9+/]+=*$") ~= nil
end

function util.is_hex_blob(s)
   if #s < 16 or #s % 2 ~= 0 then return false end
   return s:match("^[0-9a-fA-F]+$") ~= nil
end

-- Binary search for the line a byte offset falls on, given a table of line start
-- offsets (line_offsets[1] is the offset of the first character of line 1).
function util.line_of_offset(chstate, offset)
   local offsets = chstate.line_offsets or {}
   local low, high = 1, #offsets
   while low <= high do
      local middle = math.floor((low + high) / 2)
      if offsets[middle] <= offset then
         if middle == high or offsets[middle + 1] > offset then
            return middle, offset - offsets[middle] + 1
         end
         low = middle + 1
      else
         high = middle - 1
      end
   end
   return 1, 1
end

function util.trim(s)
   return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

-- Stable id for a source/target so SARIF fingerprints survive line moves.
function util.fingerprint(parts)
   local cleaned = {}
   for _, part in ipairs(parts) do
      if part then cleaned[#cleaned + 1] = tostring(part) end
   end
   return table.concat(cleaned, ":")
end

return util
