-- Rule module: payloads.
local platform_api = require "luasec.registry.platform_api"
--
-- A detector is a function(ctx). It calls ctx:emit(code, node, extra) for each
-- finding. See src/luasec/rules/context.lua for what a context offers.
--
-- Malicious Lua hides its payload: a blob, a table of byte codes, a hand-rolled
-- decoder, and only then a loader. Reporting the loader call alone says nothing;
-- what makes it a finding is the decode chain behind the argument. So both codes
-- here are stated about that chain, and every finding carries it in `trace`.
--
--   741  a code loader is handed a decoded value
--   743  an execution sink is handed a decoded value
--
-- A value we cannot trace to a decoder is reported by neither: a loader fed a
-- plain literal, or fed a value that came from a function parameter, is a
-- 703/704 shape and belongs to the taint engine, not here.
--
-- Code this module owns: 741, 743. See docs/rules.md.
local M = {}

local detectors = {}

-- ------------------------------------------------------------ vocabulary

-- The APIs that hand a chunk to the Lua interpreter. `name` on the finding is
-- the one the source actually called.
local loaders = {
   loadstring = true,
   load = true,
   loadfile = true,
   dofile = true,
}

-- The APIs that execute what they are given. A decoded value reaching one of
-- these is a 743 even when no loader was named: the payload ran either way.
local exec_sinks = {
   ["os.execute"] = true,
   ["io.popen"] = true,
   dofile = true,
   ["package.loadlib"] = true,
   ["ffi.load"] = true,
}

-- Substrings that name a decoder. Matched against the callee's own name with
-- separators dropped, so `b64_decode`, `base64Decode` and `B64DECODE` all hit.
local decoder_words = {
   base64 = true, base32 = true, b64 = true, base16 = true,
   hex = true, unhex = true, atob = true, btoa = true,
   decode = true, deobf = true, obf = true, deobfuscate = true,
   unescape = true, urlcode = true, urldecode = true,
   unpack = true, gunzip = true, inflate = true, deflate = true,
   decompress = true, uncompress = true, lzma = true, zlib = true,
   crypt = true, xor = true, rc4 = true, rot13 = true, rot47 = true,
   xxtea = true, chunkify = true, unfilter = true,
}

-- Calls that only rename or reshape a value: whatever the argument holds, the
-- result is as visible as the argument. A loader handed `tostring(x)` has not
-- been handed a decoded payload, so these are not a decode step on their own.
local transparent = {
   tostring = true, tonumber = true, type = true, select = true, rawget = true,
   rawset = true, rawequal = true, next = true, pairs = true, ipairs = true,
   setmetatable = true, getmetatable = true, pcall = true, xpcall = true,
   error = true, assert = true, print = true, require = true, unpack = true,
   ["string.format"] = true, ["string.rep"] = true, ["string.sub"] = true,
   ["string.len"] = true, ["string.byte"] = true, ["string.find"] = true,
   ["string.match"] = true, ["string.gmatch"] = true, ["string.upper"] = true,
   ["string.lower"] = true, ["string.reverse"] = true, ["string.trim"] = true,
   ["os.getenv"] = true, ["os.time"] = true, ["os.date"] = true, ["os.clock"] = true,
   ["io.open"] = true, ["io.read"] = true, ["io.lines"] = true, ["io.input"] = true,
   ["table.insert"] = true, ["table.remove"] = true, ["table.sort"] = true,
}

-- Byte-building and bit-twiddling calls. Reconstructing a string one byte at a
-- time is the decoder, whatever the surrounding code calls it.
local byte_builders = {
   ["string.char"] = true,
   ["string.unpack"] = true,
   ["bit.bxor"] = true, ["bit.band"] = true, ["bit.bor"] = true,
   ["bit.lshift"] = true, ["bit.rshift"] = true, ["bit.tobit"] = true,
   ["bit32.bxor"] = true, ["bit32.band"] = true, ["bit32.bor"] = true,
   ["bit32.lshift"] = true, ["bit32.rshift"] = true,
}

-- Work caps. A chain is short by construction; these bound the three ways a
-- crafted file could stretch one, so a scan stays proportional to file size.
local MAX_TRACE_DEPTH = 6
local MAX_DEFINITIONS = 4
local MAX_BINDINGS = 16
local MAX_BODY_NODES = 400
local MAX_BYTE_SEARCH = 64
local MAX_ALPHABET = 128

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

-- ------------------------------------------------------------ helpers

-- A stable label for a callee: `string.char` for a dotted path, `c:send` for a
-- method call, the bare identifier otherwise, and nil when the callee is an
-- expression we cannot name.
local function callee_label(ctx, call)
   local callee = call[1]
   if type(callee) ~= "table" then return nil end

   if call.tag == "Invoke" then
      -- A method call is `Invoke base, "name", args...`: the name is the
      -- call's own second slot, not a field of the base.
      local method = call[2]
      if type(method) == "table" and method.tag == "String" then
         local base = ctx:path_of(callee)
         return base and (base .. ":" .. method[1]) or method[1]
      end
      return nil
   end

   local path = ctx:path_of(callee)
   if path then return path end
   if callee.tag == "Id" and type(callee[1]) == "string" then return callee[1] end
   return nil
end

-- Does this callee name read as a decoder? Compared on the name with
-- separators dropped, so neither `_` nor case can hide the word.
local function is_decoder_name(name)
   if type(name) ~= "string" then return false end
   local squeezed = name:gsub("[%s_%-%.:]", ""):lower()
   for word in pairs(decoder_words) do
      if squeezed:find(word, 1, true) then return true end
   end
   return false
end

-- Every definition a local was given, newest last, capped.
local function definitions_of(node)
   if node.tag ~= "Id" or not node.var then return {} end
   local out = {}
   for _, value in ipairs(node.var.values or {}) do
      if value.node then
         out[#out + 1] = value.node
         if #out >= MAX_DEFINITIONS then break end
      end
   end
   return out
end

-- The Function node a callee was bound to, when the binding is visible. A
-- variable rebound thousands of times tells us nothing, so the search stops.
local function defined_function(call)
   local callee = call[1]
   if type(callee) ~= "table" or callee.tag ~= "Id" or not callee.var then return nil end
   local seen = 0
   for _, value in ipairs(callee.var.values or {}) do
      seen = seen + 1
      if value.node and value.node.tag == "Function" then return value.node end
      if seen >= MAX_BINDINGS then break end
   end
   return nil
end

-- The Table node a base expression was bound to, so `cfg.script` can be read
-- back out of the table literal the local was initialised with.
local function table_of(node)
   if node.tag ~= "Id" or not node.var then return nil end
   local seen = 0
   for _, value in ipairs(node.var.values or {}) do
      seen = seen + 1
      if value.node and value.node.tag == "Table" then return value.node end
      if seen >= MAX_BINDINGS then break end
   end
   return nil
end

-- The value of a `key = value` field in a table literal, or nil.
local function table_field(table_node, key)
   for _, pair_node in ipairs(table_node) do
      local key_node = pair_node[1]
      if pair_node.tag == "Pair" and type(key_node) == "table"
            and key_node.tag == "String" and key_node[1] == key then
         return pair_node[2]
      end
   end
   return nil
end

-- A table of byte codes: how a payload looks before it becomes a string.
local function byte_table_shape(node)
   if node.tag ~= "Table" then return nil end
   local count = #node
   if count < 3 then return nil end
   for index = 1, count do
      local item = node[index]
      if type(item) ~= "table" or item.tag ~= "Number" then return nil end
   end
   return "byte table"
end

-- A literal base64 or hex alphabet, looked up one character at a time.
local alphabets = {
   ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"] = true,
   ["ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"] = true,
   ["0123456789abcdefABCDEF"] = true,
}

local function alphabet_shape(node)
   if node.tag ~= "Table" or #node > MAX_ALPHABET then return nil end
   local chars = {}
   for index = 1, #node do
      local item = node[index]
      if type(item) ~= "table" then return nil end
      if item.tag ~= "String" or #item[1] ~= 1 then return nil end
      chars[#chars + 1] = item[1]
   end
   if #chars < 16 then return nil end
   if alphabets[table.concat(chars)] then return "alphabet table" end
   return nil
end

-- Forward declarations: the shape test and the chain walk are mutually
-- recursive, and both read the per-file index, so their order in this file is
-- not significant.
local trace_of, shape_of, subtree_has, base_key_of

-- Does this subtree read a byte out of a string, or fold one? `c:byte()`,
-- `string.byte(s)` and `bit.band` are how a blob is shifted into a character.
subtree_has = function(ctx, node, budget)
   if budget <= 0 or type(node) ~= "table" then return false end
   budget = budget - 1

   if node.tag == "Invoke" and node[2] and node[2].tag == "String" then
      if node[2][1] == "byte" then return true end
   elseif node.tag == "Call" then
      local path = ctx:path_of(node[1])
      if path == "string.byte" or (path and byte_builders[path]) then return true end
   end

   for index = 1, #node do
      local child = node[index]
      if type(child) == "table" then
         local kids = child.tag and {child} or child
         for _, sub in ipairs(kids) do
            if type(sub) == "table" and subtree_has(ctx, sub, budget) then return true end
         end
      end
   end
   return false
end

-- What a function defined in this file is, judged by its body: nil when the
-- body shows no decoder shape at all. This is what separates a hand-rolled
-- decoder from a helper that happens to be called `run`. The answer is cached
-- per file: one body, one scan, however many times it is called.
shape_of = function(ctx, fn, index)
   if type(fn) ~= "table" or fn.tag ~= "Function" then return nil end
   local cached = index.shapes[fn]
   if cached ~= nil then
      return cached or nil
   end
   -- Claim the slot before the walk, so a body that somehow reaches itself
   -- cannot re-enter.
   index.shapes[fn] = false

   local body = fn[2]
   if type(body) ~= "table" then return nil end

   local shape, shape_line
   local scanned = 0

   local function offer(candidate, line)
      if candidate and not shape then
         shape, shape_line = candidate, line
      end
   end

   local function consider(node)
      if shape or scanned >= MAX_BODY_NODES then return end
      scanned = scanned + 1
      if type(node) ~= "table" then return end

      if node.tag == "Call" then
         local label = callee_label(ctx, node)
         if label and byte_builders[label] then
            offer("byte building", node.line)
            return
         end
         if label == "tonumber" then
            for index = 2, #node do
               local argument = node[index]
               if type(argument) == "table" and argument.tag == "String" and argument[1] == "16" then
                  offer("hex conversion", node.line)
                  return
               end
            end
         end
         if label == "string.gsub" then
            for index = 2, #node do
               local argument = node[index]
               if type(argument) == "table" and argument.tag == "Function" then
                  offer("substitution decode", node.line)
                  return
               end
            end
         end
      elseif node.tag == "Invoke" then
         if node[2] and node[2].tag == "String" and node[2][1] == "gsub" then
            for index = 3, #node do
               local argument = node[index]
               if type(argument) == "table" and argument.tag == "Function" then
                  offer("substitution decode", node.line)
                  return
               end
            end
         end
      elseif node.tag == "Table" then
         offer(byte_table_shape(node), node.line)
         if not shape then offer(alphabet_shape(node), node.line) end
         return
      elseif node.tag == "Op" then
         local operator = node[1]
         if operator == "add" or operator == "sub" or operator == "mod"
               or operator == "mul" or operator == "div" or operator == "idiv" then
            if subtree_has(ctx, node, MAX_BYTE_SEARCH) then
               offer("byte arithmetic", node.line)
               return
            end
         end
      end
   end

   local function descend(node)
      for index = 1, #node do
         local child = node[index]
         if type(child) == "table" then
            if child.tag then
               consider(child)
               if not shape then descend(child) end
            else
               for _, sub in ipairs(child) do
                  if type(sub) == "table" and sub.tag then
                     consider(sub)
                     if not shape then descend(sub) end
                  end
               end
            end
         end
      end
   end

   descend(body)
   if not shape then return nil end
   local found = {name = shape, line = shape_line or fn.line}
   index.shapes[fn] = found
   return found
end

-- The chain that turns `node` into a decoded string, first step first, or nil
-- when the value is not something this file shows being decoded.
trace_of = function(ctx, node, depth, index)
   depth = depth or 0
   if depth > MAX_TRACE_DEPTH or type(node) ~= "table" then return nil end
   local tag = node.tag

   if tag == "Paren" then
      return trace_of(ctx, node[1], depth + 1, index)
   elseif tag == "String" or tag == "Number" or tag == "True"
         or tag == "False" or tag == "Nil" then
      -- A literal is not a chain. `loadstring("return 1")` is visible code.
      return nil
   elseif tag == "Table" then
      local shape = byte_table_shape(node) or alphabet_shape(node)
      if not shape then return nil end
      return {{kind = "decode", name = shape, line = node.line}}
   elseif tag == "Op" then
      -- A payload assembled from parts is decoded when any part is.
      if node[1] ~= "concat" then return nil end
      return trace_of(ctx, node[2], depth + 1, index)
         or trace_of(ctx, node[3], depth + 1, index)
   elseif tag == "Id" then
      for _, value in ipairs(definitions_of(node)) do
         local found = trace_of(ctx, value, depth + 1, index)
         if found then return found end
      end
      return nil
   elseif tag == "Index" then
      local key = node[2]
      if type(key) ~= "table" or key.tag ~= "String" then return nil end
      -- A field written anywhere in the file: `M.payload = dec(blob)`.
      local owner = base_key_of(ctx, node[1], index)
      local written = owner and index.writes[owner .. "." .. key[1]]
      if written then
         local found = trace_of(ctx, written, depth + 1, index)
         if found then return found end
      end
      -- A field of the table literal the base was initialised with.
      local base = node[1]
      if type(base) == "table" and base.tag == "Id" then
         local table_node = table_of(base)
         if table_node then
            local found = trace_of(ctx, table_field(table_node, key[1]), depth + 1, index)
            if found then return found end
         end
      end
      return nil
   elseif tag == "Call" or tag == "Invoke" then
      local label = callee_label(ctx, node)
      if not label then return nil end

      -- A function this file defines is judged by what its body does, which is
      -- stronger evidence than what it is called, so that is asked first.
      local defined = defined_function(node)
      if defined then
         local shape = shape_of(ctx, defined, index)
         if shape then
            return {
               {kind = "decode", name = defined.name or "local decoder", line = defined.line},
               {kind = "step", name = shape.name, line = shape.line},
            }
         end
         -- No shape of its own, but it may still be handed the payload: a
         -- helper given a table of byte codes is part of the chain.
      end

      if byte_builders[label] then
         return {{kind = "decode", name = "byte building", line = node.line}}
      end
      if is_decoder_name(label) then
         return {{kind = "decode", name = label, line = node.line}}
      end

      -- A wrapper such as `tostring` or `string.format` is only as opaque as
      -- what it wraps, so look through it. This is also what keeps a decoded
      -- value inside a concatenation from looking like an ordinary one.
      for position = (tag == "Invoke" and 3 or 2), #node do
         local found = trace_of(ctx, node[position], depth + 1, index)
         if found then return found end
      end
      return nil
   end

   return nil
end

-- A value produced by a call this file does not define, is not known to
-- reshape transparently, and is not a declared source: the chain behind it is
-- not readable here. That is a statement about what we can see, not about what
-- the function does, so a finding built on it is only ever low confidence.
local function opaque_call(ctx, node)
   if type(node) ~= "table" or (node.tag ~= "Call" and node.tag ~= "Invoke") then return nil end
   local label = callee_label(ctx, node)
   if not label or transparent[label] then return nil end
   if platform_api.match_source(label) then return nil end
   if defined_function(node) then return nil end
   return label
end

-- The last dotted segment of a path. Scanned by hand rather than matched with
-- `([%w_]+)$`: that pattern backtracks quadratically on a long identifier
-- followed by a non-word character, and a hostile file chooses its identifiers.
local function last_segment(path)
   local cut = 1
   for index = 1, #path do
      if path:sub(index, index) == "." then cut = index + 1 end
   end
   return path:sub(cut)
end

-- The loader API a call reaches, or nil when it is not a loader.
local function loader_of(ctx, call)
   local label = callee_label(ctx, call)
   if not label then return nil end
   if loaders[label] then return label end
   -- `M.loadstring` and friends: the last segment names the API.
   local tail = last_segment(label)
   if tail ~= label and loaders[tail] then return tail end
   return nil
end

-- A stable key for the table an `a.b` access names. A global is named by its
-- path; a local is named by the variable object itself, so two locals that
-- happen to share a name are still told apart and a write is only ever matched
-- against the read that can see it.
base_key_of = function(ctx, base, index)
   if type(base) ~= "table" then return nil end
   local path = ctx:path_of(base)
   if path then return path end
   if base.tag == "Id" and base.var then
      local key = index.bases[base.var]
      if not key then
         key = "#" .. index.next_base
         index.bases[base.var] = key
         index.next_base = index.next_base + 1
      end
      return key
   end
   return nil
end

-- What one file hands the chain walk: every `base.field = value` write, so a
-- decoded value parked in a module field is still traceable when the loader
-- reads it back, and a cache of the function shapes judged so far.
local function build_index(ctx)
   local index = {writes = {}, shapes = {}, bases = {}, next_base = 1}
   ctx:each_node(function(node)
      -- A write statement is `tag, {targets...}, {values...}`; the parser keeps
      -- no names on the parts, so the slots are read by position.
      if node.tag ~= "Set" and node.tag ~= "OpSet" then return end
      local targets, values = node[1], node[2]
      if type(targets) ~= "table" or type(values) ~= "table" then return end
      for position, lhs in ipairs(targets) do
         local key = lhs[2]
         if lhs.tag == "Index" and type(key) == "table" and key.tag == "String"
               and values[position] then
            local base = base_key_of(ctx, lhs[1], index)
            if base then index.writes[base .. "." .. key[1]] = values[position] end
         end
      end
   end)
   return index
end

-- The first argument of a call, or nil when it cannot be a decoded payload. A
-- literal is never one: it is the code, in the open, and 703 already speaks
-- about a loader whose argument the analyzer cannot fold.
local function payload_argument(ctx, call)
   local argument = ctx.args_of(call)[1]
   if not argument or ctx.literal(argument) then return nil end
   return argument
end

-- ------------------------------------------------------------ detectors

-- 741: a code loader handed a decoded value.
detectors[#detectors + 1] = function(ctx)
   local index = build_index(ctx)

   ctx:each_call(function(call)
      local loader = loader_of(ctx, call)
      if not loader then return end
      local argument = payload_argument(ctx, call)
      if not argument then return end

      local trace = trace_of(ctx, argument, 0, index)
      local confidence
      if not trace then
         -- No readable chain. A call this file does not define is still a
         -- payload we cannot see, but shape alone is all we have, so it is
         -- reported as shape and never as more.
         local label = opaque_call(ctx, argument)
         if not label then return end
         trace = {{kind = "call", name = label, line = call.line}}
         confidence = "low"
      end

      trace[#trace + 1] = {kind = "sink", name = loader, line = call.line}
      ctx:emit("741", call, {
         name = loader,
         trace = trace,
         snippet = ctx:snippet(call),
         confidence = confidence,
      })
   end)
end

-- 743: an execution sink handed a decoded value. No loader is named here on
-- purpose: `os.execute(decoded)` ran the payload without one.
detectors[#detectors + 1] = function(ctx)
   local index = build_index(ctx)

   ctx:each_call(function(call)
      local label = callee_label(ctx, call)
      if not (label and exec_sinks[label]) then return end
      local argument = payload_argument(ctx, call)
      if not argument then return end
      local trace = trace_of(ctx, argument, 0, index)
      if not trace then return end
      trace[#trace + 1] = {kind = "sink", name = label, line = call.line}
      ctx:emit("743", call, {
         name = label,
         sink = label,
         trace = trace,
         snippet = ctx:snippet(call),
         confidence = "high",
      })
   end)
end

return M
