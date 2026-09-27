-- Stable JSON rendering. Key order is fixed so two runs over the same input
-- produce byte-identical output, which is what the baseline mode depends on.
local json = {}

local ESCAPES = {
   ['"'] = '\\"', ["\\"] = "\\\\", ["\b"] = "\\b", ["\f"] = "\\f",
   ["\n"] = "\\n", ["\r"] = "\\r", ["\t"] = "\\t",
}

local function escape(str)
   return (tostring(str):gsub('[%c"\\]', function(char)
      return ESCAPES[char] or string.format("\\u%04x", char:byte())
   end))
end

local function is_array(t)
   local count = 0
   for key in pairs(t) do
      if type(key) ~= "number" then return false end
      count = count + 1
   end
   return count == #t
end

local encode

local function encode_table(value, indent, out)
   local newline, pad, inner_pad = "\n", string.rep("  ", indent), string.rep("  ", indent + 1)

   if is_array(value) then
      if #value == 0 then out[#out + 1] = "[]" return end
      out[#out + 1] = "[" .. newline
      for i, item in ipairs(value) do
         out[#out + 1] = inner_pad
         encode(item, indent + 1, out)
         if i < #value then out[#out + 1] = "," end
         out[#out + 1] = newline
      end
      out[#out + 1] = pad .. "]"
   else
      local keys = {}
      for key in pairs(value) do keys[#keys + 1] = key end
      table.sort(keys)
      if #keys == 0 then out[#out + 1] = "{}" return end
      out[#out + 1] = "{" .. newline
      for i, key in ipairs(keys) do
         out[#out + 1] = inner_pad .. '"' .. escape(key) .. '": '
         encode(value[key], indent + 1, out)
         if i < #keys then out[#out + 1] = "," end
         out[#out + 1] = newline
      end
      out[#out + 1] = pad .. "}"
   end
end

encode = function(value, indent, out)
   if type(value) == "string" then
      out[#out + 1] = '"' .. escape(value) .. '"'
   elseif type(value) == "number" or type(value) == "boolean" then
      out[#out + 1] = tostring(value)
   elseif value == nil then
      out[#out + 1] = "null"
   elseif type(value) == "table" then
      encode_table(value, indent, out)
   else
      out[#out + 1] = '"' .. escape(tostring(value)) .. '"'
   end
end

function json.encode(value, pretty)
   local out = {}
   encode(value, pretty == false and -1 or 0, out)
   if pretty == false then
      -- compact mode: strip the pretty-print whitespace we do not need
      local compact = {}
      encode(value, -1, compact)
      return (table.concat(compact):gsub("%s+", " "))
   end
   return table.concat(out)
end

return json
