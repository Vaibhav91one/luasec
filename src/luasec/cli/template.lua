-- CGILua pages: request handlers live in .html/.htm/.lp files as Lua blocks
-- (`<?lua` ... `?>`, `<%` ... `%>`, `<%=` ... `%>`) inside HTML. extract()
-- blanks the HTML but keeps every line break and column, so a finding lands
-- on the page's own line; why_cmd.lua re-reads the raw file, so its frame
-- already shows the HTML.
local template = {}

--- A path that may hold Lua blocks, by extension only, case-insensitive.
function template.is_template_path(path)
   local lower = path:lower()
   return lower:sub(-5) == ".html" or lower:sub(-4) == ".htm" or lower:sub(-3) == ".lp"
end

--- True when the text holds a block opener. Only the `lua` keyword form of
-- `<?` counts; `<?xml` is not a block.
function template.has_lua(text)
   return text:find("<?lua", 1, true) ~= nil or text:find("<%", 1, true) ~= nil
end

-- The Lua between an opener and `closer`, copied unchanged; the closer itself
-- becomes " ;" so two blocks on one line stay two statements. Runs to the end
-- of the file when the block never closes.
local function copy_until(out, text, pos, n, closer)
   while pos <= n do
      if text:sub(pos, pos + 1) == closer then
         out[#out + 1] = " "
         out[#out + 1] = ";"
         return pos + 2
      end
      out[#out + 1] = text:sub(pos, pos)
      pos = pos + 1
   end
   return pos
end

--- The Lua blocks of a page, with everything outside them blanked: every byte
-- outside a block becomes a space, every "\n" and "\r" stays, bytes inside
-- blocks are copied unchanged. The output has exactly the input's lines and
-- columns. A `<%=` opener becomes `_ =` over its own 3 bytes, so the
-- expression stays a valid statement at its own columns.
function template.extract(text)
   local out = {}
   local pos, n = 1, #text
   while pos <= n do
      if text:sub(pos, pos + 4) == "<?lua" then
         for _ = 1, 5 do out[#out + 1] = " " end
         pos = copy_until(out, text, pos + 5, n, "?>")
      elseif text:sub(pos, pos + 2) == "<%=" then
         out[#out + 1] = "_"
         out[#out + 1] = " "
         out[#out + 1] = "="
         pos = copy_until(out, text, pos + 3, n, "%>")
      elseif text:sub(pos, pos + 1) == "<%" then
         out[#out + 1] = " "
         out[#out + 1] = " "
         pos = copy_until(out, text, pos + 2, n, "%>")
      else
         local byte = text:sub(pos, pos)
         if byte == "\n" or byte == "\r" then out[#out + 1] = byte
         else out[#out + 1] = " " end
         pos = pos + 1
      end
   end
   return table.concat(out)
end

return template
