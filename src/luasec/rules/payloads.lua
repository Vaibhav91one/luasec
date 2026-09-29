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
-- The other four codes here are about what a payload does rather than how it is
-- hidden: 745 watches whoever is running it, 746 carries machine code, 749
-- installs itself into the boot, and 750 matches a published signature. Each of
-- them states one fact about one API or one byte sequence, and says which.
--
-- Code this module owns: 741, 743, 745, 746, 749, 750. See docs/rules.md.
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

-- The last dotted segment of a path, and the dotted path in front of it (with
-- no trailing separator). Scanned by hand rather than matched with
-- `([%w_]+)$`: that pattern backtracks quadratically on a long identifier
-- followed by a non-word character, and a hostile file chooses its identifiers.
local function split_last(path)
   local cut = 1
   for index = 1, #path do
      if path:sub(index, index) == "." then cut = index + 1 end
   end
   return path:sub(1, cut - 2), path:sub(cut)
end

local function last_segment(path)
   local _, tail = split_last(path)
   return tail
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

-- ------------------------------------------------------------ 745: anti-analysis
--
-- Four shapes, one question: is this code watching whoever is running it?
--
--   debug.sethook   a hook installed over the call, return or line event
--   infinite loop   a `while true do end` that never leaves
--   pcall           a dangerous call whose failure is discarded
--   os.exit         a loader that kills the interpreter once it is done
--
-- Each is a fact about one API, so `name` is that API and the finding carries
-- whatever made it a finding.

-- The debug events a hook is *called on*. A hook installed for any of them
-- runs inside the call it is watching, which is how it gets to look at the
-- caller's stack. A count-only hook (an empty mask plus a count) is called
-- every N instructions and sees nothing about the stack: that is the
-- instrumentation idiom, and reporting it would flag every profiler.
local hook_events = {c = true, r = true, l = true}

-- Does a hook mask name at least one event the hook runs inside?
local function mask_observes(mask)
   for index = 1, #mask do
      if hook_events[mask:sub(index, index)] then return true end
   end
   return false
end

-- Is the base of `x.sethook` a debug library? `setHook` on a timer or a
-- scheduler is a setter, not a trap, so the name has to say which library it
-- is before the mask is even read.
local function is_debug_base(base)
   if base == "" then return false end
   return last_segment(base):lower():find("debug", 1, true) ~= nil
end

-- Where each node keeps the statements of a body. Reading a body from a fixed
-- slot is what makes "this call is a statement" answerable at all: `Return` and
-- `local x =` also hold lists of nodes, and a value in one of those is used
-- rather than discarded.
--
-- A numeric `for` with a step keeps its body one slot further along than the
-- same loop without one, so both slots are listed. Listing a slot that holds an
-- expression instead is harmless: a list of statements has no `tag` and
-- anything that does is skipped.
local body_slots = {
   Do = {1},
   While = {2},
   Repeat = {1},
   Fornum = {4, 5},
   Forin = {3},
   Function = {2},
}

-- An `if` keeps its blocks at every even slot and its conditions at the odd
-- ones, so its body slots are not a fixed list.
local function is_body_slot(node, slot)
   if node.tag == "If" then return slot % 2 == 0 end
   local slots = body_slots[node.tag]
   if not slots then return false end
   for _, candidate in ipairs(slots) do
      if candidate == slot then return true end
   end
   return false
end

-- Visit every tagged node in the program exactly once, with the innermost
-- function that owns it, whether it sits in statement position, and whether it
-- is the last statement of the body it closes. Linear in the size of the file:
-- each node is handed to `visit` once and descended once.
local function walk_program(ast, visit, max_depth)
   local descend_node

   local function descend_list(list, owner, in_statement, depth)
      if depth <= 0 or type(list) ~= "table" or list.tag then return end
      local last = #list
      for index = 1, last do
         local item = list[index]
         if type(item) == "table" and item.tag then
            visit(item, owner, in_statement, index == last)
            descend_node(item, owner, depth - 1)
         end
      end
   end

   descend_node = function(node, owner, depth)
      if depth <= 0 or type(node) ~= "table" then return end
      local own = node.tag == "Function" and node or owner
      for slot = 1, #node do
         local child = node[slot]
         if type(child) == "table" then
            if child.tag then
               visit(child, own, false, false)
               descend_node(child, own, depth - 1)
            else
               descend_list(child, own, is_body_slot(node, slot), depth - 1)
            end
         end
      end
   end

   descend_list(ast, nil, true, max_depth)
end

-- The APIs a 745 wraps: execution, not dynamic evaluation. A `pcall` around a
-- loader is left out: the loader call is already its own 703 or 704, and
-- reporting the one call twice would teach a reader to ignore one of the two.
local suppressible = {
   ["os.execute"] = true,
   ["io.popen"] = true,
   ["package.loadlib"] = true,
   ["ffi.load"] = true,
}

-- The `debug.sethook` shape: a hook installed over the call, return or line
-- event. Read in its own pass because the argument it judges is not part of the
-- statement walk the other three shapes need.
detectors[#detectors + 1] = function(ctx)
   ctx:each_call(function(call)
      local label = callee_label(ctx, call)
      if not label then return end
      local base, tail = split_last(label)
      if tail ~= "sethook" or not is_debug_base(base) then return end

      -- The mask is the second argument. Absent means the hook is being
      -- cleared, which observes nothing.
      local mask_node = ctx.args_of(call)[2]
      if not mask_node then return end

      local mask = ctx.constant(mask_node)
      if mask == nil then
         -- The mask is computed somewhere we cannot read, so we cannot claim
         -- it names an event. The hook is still installed, and that alone is
         -- what a reader needs to know.
         ctx:emit("745", call, {
            name = "debug.sethook",
            confidence = "low",
            snippet = ctx:snippet(call),
         })
         return
      end
      if type(mask) ~= "string" or not mask_observes(mask) then return end

      ctx:emit("745", call, {
         name = "debug.sethook",
         hook_mask = mask,
         confidence = "high",
         snippet = ctx:snippet(call),
      })
   end)
end

detectors[#detectors + 1] = function(ctx)
   local spins, exits = {}, {}
   local per_function = {}

   local function owner_of(fn)
      local record = per_function[fn]
      if not record then
         record = {loaders = false, sinks = {}}
         per_function[fn] = record
      end
      return record
   end

   walk_program(ctx.chstate.ast, function(node, owner, in_statement, is_last)
      if node.tag == "Call" or node.tag == "Invoke" then
         local label = callee_label(ctx, node)
         if label then
            if loaders[label] and owner then owner_of(owner).loaders = true end
            if exec_sinks[label] and owner then owner_of(owner).sinks[label] = true end
            if in_statement and last_segment(label) == "pcall" then
               local inner = ctx.args_of(node)[1]
               if inner and (inner.tag == "Call" or inner.tag == "Invoke") then
                  local inner_label = callee_label(ctx, inner)
                  if inner_label and suppressible[inner_label] then
                     ctx:emit("745", node, {
                        name = "pcall(" .. inner_label .. ")",
                        sink = inner_label,
                        confidence = "high",
                        snippet = ctx:snippet(node),
                     })
                  end
               end
            end
         end
         -- The interpreter killed from the last line of a function that has
         -- just loaded code: the payload is in, and nothing may look at it.
         if is_last and label == "os.exit" and owner then
            exits[#exits + 1] = {call = node, owner = owner}
         end
      elseif node.tag == "While" then
         local body = node[2]
         if type(body) == "table" and not body.tag and next(body) == nil
               and (node[1].tag == "True" or ctx.constant(node[1]) == true) then
            spins[#spins + 1] = {node = node, owner = owner}
         end
      end
   end, 200)

   -- The sink a spin loop is holding the door for can sit after the loop, so
   -- the whole file is walked before the loops are judged.
   for _, spin in ipairs(spins) do
      local record = spin.owner and per_function[spin.owner]
      local sink = nil
      if record then
         for label in pairs(record.sinks) do
            sink = label
            break
         end
      end
      ctx:emit("745", spin.node, {
         name = "infinite loop",
         sink = sink,
         confidence = "medium",
         snippet = ctx:snippet(spin.node),
      })
   end

   for _, exit in ipairs(exits) do
      local record = per_function[exit.owner]
      -- The last statement of the function's own body, not the last statement
      -- of some branch inside it: `if not chunk then os.exit(2) end` is a
      -- failure exit and every service has one.
      local body = exit.owner[2]
      if record and record.loaders and type(body) == "table"
            and body[#body] == exit.call then
         ctx:emit("745", exit.call, {
            name = "os.exit",
            confidence = "high",
            snippet = ctx:snippet(exit.call),
         })
      end
   end
end

-- ------------------------------------------------------------ 746: machine code
--
-- Machine code is recognised by shape, not by a magic string on its own. Four
-- characters of ELF magic are four characters a program could have printed; what
-- makes them a blob is the header *and* a body made of bytes that no text file
-- is made of.
--
-- So a candidate has to clear a length floor and at least one of five shapes:
--
--   ELF header       the 0x7f ELF magic, and enough bytes to be a file
--   PE header        the MZ magic with a body that is not text
--   nop sled         a run of 0x90, which is alignment padding and nothing else
--   x86-64 prologue  push rbp; sub rsp, repeated: one prologue is a function,
--                    a run of them is a program written in machine code
--   shellcode        high entropy, mostly non-text bytes, and the control-flow
--                    opcodes a compiler does not emit into data
--
-- The first four are a fixed shape and speak for themselves. The fifth is the
-- only one that needs a statistical argument, so it is the only one that gets
-- one: entropy, the printable ratio, and a marker count high enough that a
-- random blob of the same size would not reach it.

local util = require "luasec.util.util"

-- The shortest blob worth calling a blob. Four bytes of magic is a header we
-- cannot say anything more about, and this file's own detection constants are
-- below the floor on purpose.
local MIN_BLOB_BYTES = 12

-- A run of 0x90 shorter than this is alignment inside a real program.
local MIN_NOP_RUN = 8

-- push rbp; sub rsp, the frame a compiler opens on every x86-64 function.
local PROLOGUE_BYTES = string.char(48, 131)

-- Control-flow and stack opcodes. A JPEG or a zip entry is not made of them,
-- hand-written machine code mostly is, and three of them in sixteen bytes is
-- not something compressed data does often.
local CODE_MARKERS = {
   [0x0f] = true,  -- two-byte opcode prefix, syscall and friends
   [0x31] = true, [0x33] = true,   -- xor reg, reg: how a stub clears it
   [0x68] = true, [0x6a] = true,   -- push imm32, push imm8
   [0x89] = true, [0x8b] = true,   -- mov reg, reg
   [0x99] = true,  -- cdq
   [0xb8] = true,  -- mov eax, imm32
   [0xcc] = true,  -- int3
   [0xcd] = true,  -- int 0x80
   [0xe8] = true,  -- call rel32
   [0xe9] = true,  -- jmp rel32
   [0xeb] = true,  -- jmp rel8
}

-- The shellcode class is the one statistical call in this detector, so it is
-- also the only one reported as a guess rather than as a shape.
local MIN_SHELLCODE_BYTES = 16
local MIN_MARKERS = 3
local MIN_BLOB_ENTROPY = 3.5
local MAX_PRINTABLE_RATIO = 0.5

-- One pass over a candidate, collecting every number the shapes are judged on.
-- Nothing here is a Lua pattern: a pattern over attacker-chosen bytes is a way
-- to spend a reader's CPU, and a plain byte loop is linear by construction.
local function measure(s)
   local stats = {bytes = #s, printable = 0, markers = 0, longest_nop = 0, prologues = 0}
   local run = 0
   for index = 1, #s do
      local byte = s:byte(index)
      if byte >= 32 and byte <= 126 then
         stats.printable = stats.printable + 1
      end
      if CODE_MARKERS[byte] then
         stats.markers = stats.markers + 1
      end
      if byte == 0x90 then
         run = run + 1
         if run > stats.longest_nop then stats.longest_nop = run end
      else
         run = 0
      end
      if byte == 0x30 and s:byte(index + 1) == 0x83 then
         stats.prologues = stats.prologues + 1
      end
   end
   stats.entropy = util.entropy(s)
   return stats
end

-- The shape a candidate is, its length, and how sure we are. Ordered most
-- specific first, so an ELF header with a NOP run in it is reported as the
-- header it is.
local function shape_of(s)
   if #s < MIN_BLOB_BYTES then return nil end
   local stats = measure(s)

   if s:byte(1) == 0x7f and s:sub(2, 4) == "ELF" then
      return "ELF header", stats.bytes, "high"
   end
   if s:sub(1, 2) == "MZ" and stats.printable <= stats.bytes * MAX_PRINTABLE_RATIO then
      return "PE header", stats.bytes, "high"
   end
   if stats.longest_nop >= MIN_NOP_RUN then
      return "nop sled", stats.longest_nop, "high"
   end
   if stats.prologues >= 3 then
      return "x86-64 prologue", stats.prologues * #PROLOGUE_BYTES, "high"
   end
   if stats.bytes >= MIN_SHELLCODE_BYTES and stats.markers >= MIN_MARKERS
         and stats.entropy >= MIN_BLOB_ENTROPY
         and stats.printable <= stats.bytes * MAX_PRINTABLE_RATIO then
      return "shellcode", stats.bytes, "medium"
   end
   return nil
end

-- The bytes a `string.char(...)` or `string.unpack(...)` call spells out, or
-- nil when any argument is not a whole number we can hold. The parser keeps a
-- numeric literal as the text it was written as, so the arguments are read
-- through `tonumber`. Built a chunk at a time: one call can carry thousands of
-- arguments, and handing ten thousand of them to a single C call is a stack
-- overflow waiting for a file to trigger.
local function folded_bytes(ctx, call)
   local args = ctx.args_of(call)
   if #args == 0 then return nil end
   local out, chunk = {}, {}
   for index = 1, #args do
      local value = ctx.constant(args[index])
      if type(value) == "string" then value = tonumber(value) end
      if type(value) ~= "number" or value % 1 ~= 0 or value < 0 or value > 255 then
         return nil
      end
      chunk[#chunk + 1] = string.char(value)
      if #chunk == 512 then
         out[#out + 1] = table.concat(chunk)
         chunk = {}
      end
   end
   if #chunk > 0 then out[#out + 1] = table.concat(chunk) end
   return table.concat(out), #args
end

detectors[#detectors + 1] = function(ctx)
   local function report(node, bytes, source)
      local name, length, confidence = shape_of(bytes)
      if not name then return end
      ctx:emit("746", node, {
         name = name,
         length = length,
         byte_source = source,
         confidence = confidence,
      })
   end

   -- A literal is the blob in the open. Its snippet is deliberately not
   -- carried: a megabyte of bytes in a report helps nobody, and `length` says
   -- how much there is.
   ctx:each_string(function(node, text)
      report(node, text, "string literal")
   end)

   ctx:each_call(function(call, path)
      if path ~= "string.char" and path ~= "string.unpack" then return end
      local bytes = folded_bytes(ctx, call)
      if bytes then report(call, bytes, path) end
   end)
end

-- ------------------------------------------------------------ 749: persistence
--
-- Persistence is a write to somewhere the device reads before it asks us
-- anything: a boot script, an init directory, a unit directory, a cron
-- directory, or a firewall rule. The finding is that the write happened and
-- where, so `path` is the target and `name` is the mechanism.
--
-- What is deliberately *not* part of it is the path being mentioned. A string
-- that contains "/etc/rc.local" is a path a script read, printed, or put in an
-- error message; a write to it is a decision. A write to /tmp is a decision
-- too, and the reboot is what makes it harmless.
--
-- Firmware.lua owns 721 and 726, which are about a write to firmware
-- configuration whatever is written in it. This code is about the other half:
-- the file it lands in is what runs at boot, so the install outlives the
-- script that made it.

-- The files the boot reads. Compared, never matched: `exact` and `prefixes` are
-- string comparisons, so no input can make them backtrack and a path that
-- merely contains one of these ("/tmp/etc/init.d/x") does not match.
local BOOT_PATHS = {
   exact = {
      "/etc/rc.local", "/etc/rc.d/rc.local", "/etc/inittab", "/etc/profile",
   },
   prefixes = {
      "/etc/init.d/", "/etc/rc.d/", "/etc/rc0.d/", "/etc/rc1.d/", "/etc/rc2.d/",
      "/etc/rc3.d/", "/etc/rc4.d/", "/etc/rc5.d/", "/etc/rc6.d/", "/etc/rcS.d/",
      "/etc/uci-defaults/",
      "/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/",
      "/run/systemd/system/",
      "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
      "/etc/cron.weekly/", "/etc/cron.monthly/",
   },
}

local function is_boot_path(path)
   for _, exact in ipairs(BOOT_PATHS.exact) do
      if path == exact then return true end
   end
   for _, prefix in ipairs(BOOT_PATHS.prefixes) do
      if path:sub(1, #prefix) == prefix then return true end
   end
   return false
end

-- The openers that write, and where their mode says so. `io.open` defaults to
-- reading, so an absent or read-only mode is a read and is not a finding.
local openers = {
   ["io.open"] = true,
   ["io.output"] = true,
}

-- Does this mode write? The first character decides: w truncates, a appends,
-- and a "+" anywhere opens the other direction as well.
local function mode_writes(mode)
   if type(mode) ~= "string" or mode == "" then return false end
   local first = mode:sub(1, 1)
   if first == "w" then return true end
   if first == "a" then return true end
   return mode:find("+", 1, true) ~= nil
end

-- The word a shell command hands to crontab. `crontab -l` lists and
-- `crontab -r` is empty, but replacing the table is the install, and so is
-- pointing crontab at a file that was just written. The command is searched
-- anywhere in the line, because the usual shape pipes the table in and crontab
-- is the last word of it.
local function crontab_installed(command)
   local at = command:find("crontab", 1, true)
   if not at then return false end
   -- The word before it must end here, or this is `mycrontab` or `crontabx`.
   if at > 1 and command:sub(at - 1, at - 1):match("[%w_]") then return false end
   local argument = command:sub(at + 7):gsub("^%s+", "")
   local space = argument:find("%s")
   local word = space and argument:sub(1, space - 1) or argument
   return not (word == "-l" or word == "--list" or word == "")
end

-- The first two words of a command and everything after them.
--
-- `systemctl enable x`, `/usr/bin/systemctl enable x` and
-- `env FOO=1 systemctl enable x` are the same command, so leading `KEY=value`
-- assignments are skipped and only the program and its first argument are
-- read. The scan stops at two words either way: a command is whatever the file
-- says, and the further in it goes the more of it there is to walk.
local MAX_COMMAND_WORDS = 2

local function command_words(command)
   local words = {}
   local rest = command
   while #words < MAX_COMMAND_WORDS do
      rest = rest:gsub("^%s+", "")
      if rest == "" then return words, "" end
      local at = rest:find("%s")
      local word = at and rest:sub(1, at - 1) or rest
      if word:sub(1, 1) ~= "-" and not word:find("=") then
         words[#words + 1] = word
         if #words == MAX_COMMAND_WORDS then
            return words, at and rest:sub(at + 1) or ""
         end
      end
      if not at then return words, "" end
      rest = rest:sub(at + 1)
   end
   return words, ""
end

local function program_of(words)
   return last_segment(words[1] or ""):lower()
end

-- The paths a `>`, `>>` or `&>` in a command writes to. Read by hand, because
-- the alternative is matching the command with a pattern and a command is
-- whatever the file says it is.
local function redirect_targets(command)
   local targets = {}
   local from = 1
   while true do
      local at = command:find(">", from, true)
      if not at then return targets end
      from = at + 1
      -- `>&2` and `2>&1` are a descriptor, not a file.
      local rest = command:sub(at + 1):gsub("^&", "")
      local stop = rest:find("[%s;|&<>()]")
      local word = stop and rest:sub(1, stop - 1) or rest
      -- A redirect with nothing after it names no file, and there is nothing
      -- later in the command that could: the next character is a separator or
      -- the string ends.
      if word == "" then return targets end
      -- A word with no separator in it is a file descriptor or a comparison,
      -- not a path.
      if word:find("/", 1, true) then targets[#targets + 1] = word end
   end
end

-- The uci options that turn a firewall rule into an open port. A uci write to
-- the firewall package is a rule the device enforces; setting the port is what
-- makes the service reachable.
local port_options = {
   "dest_port", "src_dport",
}

-- Does this text set a port on a firewall rule? Both facts are needed: a uci
-- write to `network.wan.proto` changes configuration, and a write to
-- `firewall` that touches no port opens nothing.
local function opens_firewall_port(text)
   if type(text) ~= "string" then return false end
   if text:find("firewall", 1, true) == nil then return false end
   for _, option in ipairs(port_options) do
      if text:find(option, 1, true) then return true end
   end
   return false
end

-- The text a uci option names, as far as it is written in the file.
--
-- `uci.set("firewall.@rule[0].dest_port=" .. port)` is the common spelling and
-- it never folds to a constant, so the literal halves of the concatenation are
-- read instead. Only the halves are joined: a value spliced in is unknown, and
-- a rule whose port is a variable is still a rule that opens one.
local MAX_OPTION_PARTS = 16
local MAX_OPTION_DEPTH = 8

local function option_text(ctx, node)
   if type(node) ~= "table" then return nil end
   if node.tag == "String" then return node[1] end
   if node.tag ~= "Op" or node[1] ~= "concat" then
      return ctx.constant(node)
   end
   -- The halves are joined with a byte that cannot appear in a uci option, so
   -- two adjacent literals cannot be read as one longer one.
   local parts, budget = {}, MAX_OPTION_PARTS
   local function collect(inner, depth)
      if budget <= 0 or depth > MAX_OPTION_DEPTH or type(inner) ~= "table" then return end
      budget = budget - 1
      if inner.tag == "String" then
         parts[#parts + 1] = inner[1]
      elseif inner.tag == "Op" and inner[1] == "concat" then
         collect(inner[2], depth + 1)
         collect(inner[3], depth + 1)
      end
   end
   collect(node, 0)
   if #parts == 0 then return nil end
   return table.concat(parts, "\1")
end

-- The uci calls that change configuration. `uci.get` is not one of them: a read
-- of the firewall package opens nothing.
local uci_verbs = {
   set = true, add = true, sets = true, append = true, commit = true,
   set_list = true,
}

-- Is this a call that configures uci? `uci.set`, `luci.model.uci.set` and
-- `uci:set` are the three spellings, and they differ only in the table they name.
local function is_uci_call(label)
   local base, verb = split_last(label)
   if not uci_verbs[verb] then return false end
   return base:lower():find("uci", 1, true) ~= nil
end

-- The words that say the install was fetched and made runnable. Reported on the
-- finding because a boot script written from an image and one downloaded onto
-- the device are very different things to clean up.
local stage_words = {
   {word = "chmod", label = "chmod"},
   {word = "wget", label = "download"},
   {word = "curl", label = "download"},
   {word = "tftp", label = "download"},
   {word = "http://", label = "download"},
   {word = "https://", label = "download"},
}

-- The longest string literal a file is allowed to spend on the staging scan.
local MAX_STAGE_SCAN = 4096

-- How the script got the file it installed, as the labels of the words that
-- appear anywhere in its own strings, in a fixed order so two files that both
-- fetch and chmod report the same thing.
local function staging_of(ctx)
   local found, order = {}, {}
   ctx:each_string(function(_, text)
      if type(text) ~= "string" or #text > MAX_STAGE_SCAN then return end
      for _, entry in ipairs(stage_words) do
         if not found[entry.label] and text:find(entry.word, 1, true) then
            found[entry.label] = true
            order[#order + 1] = entry.label
         end
      end
   end)
   return order
end

-- One install: the node to point at, the target, the mechanism, and what the
-- rest of the file says about how the file got there.
local function persistence(ctx, node, path, name, staged, downloaded)
   local extra = {name = name, path = path, confidence = "high"}
   if staged ~= "" then extra.staged = staged end
   if downloaded then extra.downloaded = true end
   ctx:emit("749", node, extra)
end

detectors[#detectors + 1] = function(ctx)
   local staging = staging_of(ctx)
   local staged, downloads = table.concat(staging, ", "), false
   for _, label in ipairs(staging) do
      if label == "download" then downloads = true end
   end

   local function command_arguments(node, label)
      if label == "os.execute" or label == "io.popen" then
         return true, ctx.literal(ctx.args_of(node)[1])
      end
      local sink = platform_api.match_sink(label)
      return sink ~= nil and sink.kind == "exec", nil
   end

   ctx:each_call(function(call, path)
      local label = callee_label(ctx, call)
      if not label then return end

      -- A file opened for writing under a boot path. The last segment is read
      -- too so that `nixio.open` is a write as much as `io.open` is.
      if openers[label] or openers[last_segment(label)] then
         local args = ctx.args_of(call)
         local target = ctx.constant(args[1])
         local mode = ctx.constant(args[2])
         if type(target) == "string" and is_boot_path(target) and mode_writes(mode) then
            local appending = type(mode) == "string" and mode:sub(1, 1) == "a"
            persistence(ctx, call, target,
               appending and "boot file append" or "boot file write", staged, downloads)
            return
         end
      end

      local is_shell, text = command_arguments(call, label)
      if not is_shell then
         -- A uci write is a persistence install of its own kind, and it needs
         -- the text of the option rather than a path.
         if not is_uci_call(label) then return end
         for _, argument in ipairs(ctx.args_of(call)) do
            if opens_firewall_port(option_text(ctx, argument)) then
               persistence(ctx, call, "firewall", "uci firewall rule", staged, downloads)
               return
            end
         end
         return
      end

      if type(text) ~= "string" or text == "" then return end

      -- crontab is not the first word of the usual install: the table is
      -- piped into it.
      if crontab_installed(text) then
         persistence(ctx, call, "crontab", "crontab install", staged, downloads)
         return
      end

      local words, rest = command_words(text)
      if words[1] == nil then return end
      local program = program_of(words)

      if program == "systemctl" or program == "rc-update" or program == "update-rc.d" then
         local verb = words[2]
         if verb == "enable" or verb == "add" or verb == "--enable" or verb == "--add" then
            local unit = rest:match("^%s*([^%s]+)")
            persistence(ctx, call, unit or "", program .. " enable", staged, downloads)
         end
         return
      end

      for _, target in ipairs(redirect_targets(text)) do
         if is_boot_path(target) then
            persistence(ctx, call, target, "shell redirect", staged, downloads)
         end
      end
   end)
end

-- ------------------------------------------------------------ 750: signatures
--
-- The pack itself is data, in src/luasec/registry/stds/signatures.lua. This
-- detector does three things with it and nothing else: it loads the pack, it
-- matches every signature against the file, and it reports the id and the pack
-- version on every finding so a report says which pack made the claim.
--
-- A signature is matched against the file's text and against its string
-- literals, and the two passes cannot report the same hit twice:
--
--   pass one, the string literals in source order, which is where a payload
--           keeps its configuration and gives the finding an exact position
--   pass two, the rest of the file's text: its comments and the names it binds
--           its variables to. A file is literals, comments, names, numbers and
--           punctuation, so a signature that holds a letter cannot hide in the
--           other two - and a payload does not have to put its string in a
--           string. A comment is left behind by whoever deployed it; a variable
--           named after a default credential is the credential table's own
--           doing.
--
-- A signature is reported once per file, at its first match. A file with the
-- same password in four places is one file with one problem, and four findings
-- saying so helps nobody.

-- A pack that does not hold together is a packaging error, not a finding about
-- the file being analyzed, so it is raised once at load rather than reported
-- as a 750 that matches nothing.
local function prepare_pack()
   local pack = require "luasec.registry.stds.signatures"
   assert(type(pack) == "table" and type(pack.version) == "string" and pack.version ~= "",
      "signature pack: a version is required")
   assert(type(pack.signatures) == "table" and #pack.signatures > 0,
      "signature pack: at least one signature is required")

   local entries, ids = {}, {}
   for index, signature in ipairs(pack.signatures) do
      local at = "signature pack entry " .. index
      assert(type(signature) == "table", at .. " must be a table")
      assert(type(signature.id) == "string" and signature.id ~= "",
         at .. " needs an id")
      assert(type(signature.description) == "string" and signature.description ~= "",
         at .. " needs a description")
      assert(type(signature.pattern) == "string" and signature.pattern ~= "",
         at .. " needs a pattern")
      assert(not ids[signature.id], "signature pack: duplicate id " .. signature.id)
      ids[signature.id] = true

      -- Alternatives are split once, here, and matched as plain substrings
      -- after that. A pattern in the data would be a pattern matched against
      -- attacker-chosen bytes.
      local alternatives, shortest = {}, nil
      for piece in (signature.pattern .. "|"):gmatch("([^|]*)|") do
         assert(piece ~= "", "signature pack: empty alternative in " .. signature.id)
         alternatives[#alternatives + 1] = piece
         if not shortest or #piece < shortest then shortest = #piece end
      end

      entries[#entries + 1] = {
         id = signature.id,
         description = signature.description,
         reference = signature.reference,
         alternatives = alternatives,
         shortest = shortest,
      }
   end
   return {version = pack.version, entries = entries}
end

local prepared_pack
local function signature_pack()
   if not prepared_pack then prepared_pack = prepare_pack() end
   return prepared_pack
end

-- The node a match found outside a string literal is reported at. A comment and
-- a name both know their own line, and both are single lines, so the position
-- is the line and its first column: pointing at the right line of a comment is
-- what a reader needs, and there is no column inside a name worth arguing over.
local function text_node(line)
   return {line = line or 1, offset = 1, end_offset = 1}
end

-- Every name the file binds, and every comment it carries, each once, with the
-- first line it appeared on. Deduplicated because a name is bound once and read
-- a hundred times, and searching the same eight characters a hundred times is
-- work for nothing.
local function texts_outside_literals(ctx)
   local seen, texts = {}, {}

   local function offer(text, line)
      if type(text) ~= "string" or text == "" or seen[text] then return end
      seen[text] = true
      texts[#texts + 1] = {text = text, line = line}
   end

   ctx:each_node(function(node)
      if node.tag == "Id" or node.tag == "Field" then
         offer(node[1], node.line)
      end
   end)

   for _, comment in ipairs(ctx.chstate.comments or {}) do
      offer(comment.contents, comment.line)
   end

   return texts
end

detectors[#detectors + 1] = function(ctx)
   local pack = signature_pack()
   local reported = {}

   local function report(node, entry)
      if reported[entry.id] then return end
      reported[entry.id] = true
      ctx:emit("750", node, {
         name = entry.id,
         signature = entry.id,
         description = entry.description,
         pack_version = pack.version,
         reference = entry.reference,
         confidence = "certain",
      })
   end

   local function match(entry, text)
      if #text < entry.shortest then return false end
      for _, alternative in ipairs(entry.alternatives) do
         if text:find(alternative, 1, true) then return true end
      end
      return false
   end

   -- Pass one: the string literals, in source order, so the first hit of a
   -- signature is reported at the earliest place the signature appears.
   ctx:each_string(function(node, text)
      if type(text) ~= "string" then return end
      for _, entry in ipairs(pack.entries) do
         if not reported[entry.id] and match(entry, text) then
            report(node, entry)
         end
      end
   end)

   -- Pass two: the rest of the file's text.
   for _, candidate in ipairs(texts_outside_literals(ctx)) do
      for _, entry in ipairs(pack.entries) do
         if not reported[entry.id] and match(entry, candidate.text) then
            report(text_node(candidate.line), entry)
         end
      end
   end
end

return M
