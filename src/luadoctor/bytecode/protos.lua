-- Walk the prototype tree of a precompiled chunk.
--
-- A prototype (Proto in lobject.h) carries a source name, a line range, a code
-- vector, a constant table, upvalue descriptors, nested prototypes and debug
-- information. Triage needs the source, the line count, the upvalue names and
-- the constant table, so we read those and skip the code vector.
--
-- The four versions do not agree on the encoding, which is the whole reason the
-- differences live in a table (LAYOUTS below) rather than in one reader:
--
--             5.1         5.2         5.3         5.4
--   int       int32       int32       int32       varint
--   size_t    native      native      byte|0xFF   varint
--   tags      plain       plain       variant     variant
--   string    NUL in file NUL in file NUL out     NUL out
--   upvalues  in frame    own block   own block   own block +kind
--   protos    after const after const after      after
--             only        upvalues    upvalues    upvalues
--   source    head        debug head  head        head
--   debug     li,loc,uv   src,li,loc, li,loc,uv   li,abs,loc,uv
--                       ,uv
--   closure   no byte     no byte     1 byte      1 byte
--   lineinfo  4 bytes     4 bytes     4 bytes     1 byte
--
-- Three caps bound the walk, each a property of this module rather than of any
-- input:
--
--   MAX_CONSTANTS  100000  constants read in total
--   MAX_DEPTH          64  prototype nesting
--   MAX_PROTOS     100000  prototypes visited
--
-- Every length is compared against the bytes actually present before anything
-- is taken from the string, so a chunk claiming a gigabyte costs one
-- comparison. Hitting a cap or a bound stops the walk and is reported through
-- `truncated`; nothing here raises.
local header = require "luadoctor.bytecode.header"

local protos = {}

protos.MAX_CONSTANTS = 100000
protos.MAX_DEPTH = 64
protos.MAX_PROTOS = 100000

-- Constant tag -> payload kind, per version. 5.1 and 5.2 dump plain type
-- numbers (lua.h). 5.3 and 5.4 dump variants, where makevariant(t, v) is
-- t | v << 4 (lobject.h); 5.3 spells the numbers the other way round from 5.4
-- and spells a boolean as one tag with a trailing byte where 5.4 has two
-- payload-free tags.
--
-- kind is one of: none, bool, string, number (double), integer.
local function tag_table(spec)
   local out = {}
   for tag, kind in pairs(spec) do out[tag] = kind end
   return out
end

local PLAIN = tag_table {
   [0] = "none",   -- LUA_TNIL
   [1] = "bool",   -- LUA_TBOOLEAN, then one byte
   [3] = "number", -- LUA_TNUMBER
   [4] = "string", -- LUA_TSTRING
}

local VARIANT_53 = tag_table {
   [0] = "none",      -- LUA_TNIL
   [1] = "bool",      -- LUA_TBOOLEAN, then one byte
   [3] = "number",    -- LUA_TNUMFLT
   [4] = "string",    -- LUA_TSHRSTR
   [19] = "integer",  -- LUA_TNUMINT
   [20] = "string",   -- LUA_TLNGSTR
}

local VARIANT_54 = tag_table {
   [0] = "none",      -- LUA_VNIL
   [1] = "none",      -- LUA_VFALSE
   [3] = "integer",   -- LUA_VNUMINT
   [4] = "string",    -- LUA_VSHRSTR
   [17] = "none",     -- LUA_VTRUE
   [19] = "number",   -- LUA_VNUMFLT
   [20] = "string",   -- LUA_VLNGSTR
}

-- How each version encodes a field. `int` and `size` differ between 5.4 and
-- the rest; the boolean and debug flags describe structural differences.
local LAYOUTS = {
   ["5.1"] = {
      tags = PLAIN,
      int = "int32",
      size = "size_t",
      nul_in_string = true,
      lineinfo_width = 4,
      frame_upvalues = true,   -- nups sits in the frame description
      upvalue_block = false,
      protos_after_upvalues = false,
      source_in_debug = false,
      abslineinfo = false,
   },
   ["5.2"] = {
      tags = PLAIN,
      int = "int32",
      size = "size_t",
      nul_in_string = true,
      lineinfo_width = 4,
      frame_upvalues = false,
      upvalue_block = true,
      upvalue_block_bytes = 2,
      protos_after_upvalues = false,
      source_in_debug = true,
      abslineinfo = false,
   },
   ["5.3"] = {
      tags = VARIANT_53,
      int = "int32",
      size = "size_53",
      nul_in_string = false,
      lineinfo_width = 4,
      frame_upvalues = false,
      upvalue_block = true,
      upvalue_block_bytes = 2,
      protos_after_upvalues = true,
      source_in_debug = false,
      abslineinfo = false,
      closure_upvalue_byte = true,
   },
   ["5.4"] = {
      tags = VARIANT_54,
      int = "varint",
      size = "varint",
      nul_in_string = false,
      lineinfo_width = 1,
      frame_upvalues = false,
      upvalue_block = true,
      upvalue_block_bytes = 3,
      protos_after_upvalues = true,
      source_in_debug = false,
      abslineinfo = true,
      closure_upvalue_byte = true,
   },
}

-- ---------------------------------------------------------------- reader

-- A cursor over the byte string. Every read goes through one, so "past the
-- end" is a value the caller handles rather than an error it has to catch.
local function reader(bytes, pos, sizes, layout)
   local self = {bytes = bytes, pos = pos, sizes = sizes, layout = layout}

   function self:remaining()
      return #bytes - self.pos + 1
   end

   function self:byte()
      local value = bytes:byte(self.pos)
      if value == nil then return nil, "truncated" end
      self.pos = self.pos + 1
      return value
   end

   function self:skip(count)
      if type(count) ~= "number" or count < 0 or count > self:remaining() then
         return nil, "past the end of the file"
      end
      self.pos = self.pos + count
      return true
   end

   -- A native width read, little endian: 5.1 to 5.3 store ints, size_t,
   -- lua_Integer and lua_Number as machine words. 5.4 stores none of them, so
   -- this is only reached for the older layouts.
   function self:fixed(width, what)
      local value, pos = header.read_integer(bytes, self.pos, width, "little", what)
      if not value then return nil, "truncated" end
      self.pos = pos
      return value
   end

   -- The 5.4 encoding (ldump.c dumpSize, lundump.c loadUnsigned): 7 bit
   -- groups, most significant first, with the high bit set on the LAST group
   -- to mark the end of the run. So 0x80 is the value 0 and 0x01 0x81 is 129.
   function self:varint()
      local value = 0
      for _ = 1, 10 do
         local byte = self:byte()
         if not byte then return nil, "truncated" end
         value = (value * 128) + (byte % 128)
         if byte >= 0x80 then return value end
      end
      return nil, "integer overflow"
   end

   function self:int()
      if self.layout.int == "varint" then return self:varint() end
      return self:fixed(sizes.int, "an int")
   end

   -- String and array lengths. 5.1 and 5.2 store a native size_t, 5.3 stores a
   -- byte that means "a size_t follows" when it is 0xFF, and 5.4 a varint.
   function self:size()
      local kind = self.layout.size
      if kind == "varint" then return self:varint() end
      if kind == "size_53" then
         local first = self:byte()
         if not first then return nil, "truncated" end
         if first == 0xFF then return self:fixed(sizes.size_t, "a size") end
         return first
      end
      return self:fixed(sizes.size_t, "a size")
   end

   -- A length of zero is not an error: the reference loader calls it a NULL
   -- string and inherits the parent's, so ABSENT is a value, not a failure.
   --
   -- The value is always `length - 1` bytes, since the count includes a
   -- trailing NUL that is not part of the string. Whether the NUL is also
   -- written out is the one difference between the two families:
   --
   --   5.1  DumpBlock(getstr(s), size)  size = len + 1, so the NUL is there
   --   5.4  dumpVector(D, str, size)    size = len, so it is not
   function self:string()
      local length = self:size()
      if not length then return nil, "truncated" end
      if length == 0 then return protos.ABSENT end

      local stored = self.layout.nul_in_string and length or (length - 1)
      if stored < 1 then return nil, "negative string length" end
      if stored > self:remaining() then return nil, "string longer than the file" end

      local text = self.bytes:sub(self.pos, self.pos + length - 2)
      self.pos = self.pos + stored
      return text
   end

   function self:double()
      return self:fixed(sizes.lua_Number, "a number")
   end

   function self:integer()
      return self:fixed(sizes.lua_Integer or 8, "an integer")
   end

   return self
end

-- ---------------------------------------------------------------- constants

-- What `cursor:string()` returns for a stored length of zero. The reference
-- loader treats that as a NULL string and inherits the parent's, so it is a
-- legitimate value rather than a failure. A table with a tostring, so a
-- half-read prototype can still be printed in a diagnostic.
protos.ABSENT = setmetatable({}, {__tostring = function() return "<absent>" end})

-- Read one constant into `list` at `index`. Returns true, or false plus a
-- reason. A tag we do not know is a corrupt chunk, not something to guess at.
local function read_constant(cursor, list, index)
   local tag = cursor:byte()
   if not tag then return false, "truncated constant tag" end

   local kind = cursor.layout.tags[tag]
   if kind == nil then return false, "unknown constant tag " .. tostring(tag) end

   if kind == "none" then
      return true
   elseif kind == "bool" then
      return cursor:byte() ~= nil, "truncated constant boolean"
   elseif kind == "string" then
      local text = cursor:string()
      if not text then return false, "truncated constant string" end
      list[index] = text
      return true
   elseif kind == "number" then
      local value = cursor:double()
      if not value then return false, "truncated constant number" end
      list[index] = value
      return true
   elseif kind == "integer" then
      local value = cursor:integer()
      if not value then return false, "truncated constant integer" end
      list[index] = value
      return true
   end

   return false, "unhandled constant kind " .. tostring(kind)
end

-- ---------------------------------------------------------------- walk

local walk_function

-- The walk is over: either a bound was hit or the bytes ran out. The first
-- reason wins, because it is the one that explains the rest.
local function halt(state, reason)
   if not state.truncated then
      state.truncated = true
      state.reason = reason
   end
   return false
end

-- A NULL string is legal everywhere a string can appear: the reference loader
-- substitutes the parent's source name and leaves local and upvalue names
-- empty. Only a real truncation is a failure.
local function read_optional_string(cursor, field)
   local text = cursor:string()
   if text == nil then return nil, "truncated " .. field end
   if text == protos.ABSENT then return nil end
   return text
end

local function read_upvalue_names(cursor, proto, state)
   local count = cursor:int()
   if not count then return halt(state, "truncated upvalue name count") end
   -- One size byte is the floor per name.
   if count > cursor:remaining() then
      return halt(state, "upvalue name count past the end of the file")
   end
   for index = 1, count do
      local name, reason = read_optional_string(cursor, "upvalue name")
      if reason then return halt(state, reason) end
      if name then proto.upvalues[index] = name end
   end
   return true
end

local function read_locvars(cursor, state)
   local count = cursor:int()
   if not count then return halt(state, "truncated local count") end
   -- A size byte plus two ints is the floor per local.
   if count * 3 > cursor:remaining() then
      return halt(state, "local count past the end of the file")
   end
   for _ = 1, count do
      local name, reason = read_optional_string(cursor, "local name")
      if reason then return halt(state, reason) end
      if not cursor:int() or not cursor:int() then
         return halt(state, "truncated local range")
      end
   end
   return true
end

local function read_debug(cursor, proto, state)
   local layout = cursor.layout

   -- 5.2 is the one version that opens the debug block with the source name
   -- instead of putting it at the head of the prototype, so it is read first.
   if layout.source_in_debug then
      local source, reason = read_optional_string(cursor, "source name")
      if reason then return halt(state, reason) end
      if source then proto.source = source end
   end

   local sizelineinfo = cursor:int()
   if not sizelineinfo then return halt(state, "truncated line info count") end
   if not cursor:skip(sizelineinfo * layout.lineinfo_width) then
      return halt(state, "line info past the end of the file")
   end

   if layout.abslineinfo then
      local sizeabs = cursor:int()
      if not sizeabs then return halt(state, "truncated abs line info count") end
      -- Each entry is two ints, so two bytes is the floor.
      if sizeabs * 2 > cursor:remaining() then
         return halt(state, "abs line info count past the end of the file")
      end
      for _ = 1, sizeabs * 2 do
         if not cursor:int() then return halt(state, "truncated abs line info") end
      end
   end

   -- Every version reads locals before upvalue names.
   if not read_locvars(cursor, state) then return false end
   if not read_upvalue_names(cursor, proto, state) then return false end
   return true
end

-- Fill `proto` from `cursor`, recursing into child prototypes. `inherited` is
-- the parent's source name: a NULL source means "same as my parent", which is
-- how every version except 5.2 records a nested function's origin.
local read_protos

walk_function = function(cursor, state, depth, inherited)
   if depth > protos.MAX_DEPTH then
      return halt(state, "prototype nesting deeper than " .. protos.MAX_DEPTH)
   end
   if state.protos_read >= protos.MAX_PROTOS then
      return halt(state, "more than " .. protos.MAX_PROTOS .. " prototypes")
   end
   state.protos_read = state.protos_read + 1

   local layout = cursor.layout
   local proto = {constants = {}, upvalues = {}}
   -- Registered before the fields are read, so a parent always precedes its
   -- nested functions in the result. A prototype that turns out to be
   -- unreadable is removed again below.
   state.protos[#state.protos + 1] = proto

   -- Each field is read only while `ok` holds, so a chunk that ran out of bytes
   -- partway through is not read further. The first failure supplies the reason;
   -- later ones are consequences of it.
   local ok = true
   local function step(condition, reason)
      if not condition then
         if ok then halt(state, reason) end
         ok = false
      end
      return condition
   end

   -- 5.1, 5.3 and 5.4 start with the source name; 5.2 records it in the debug
   -- block. A NULL source name is legal and means "same as my parent", so
   -- `origin` is what a child inherits.
   local origin = inherited
   proto.source = inherited
   if not layout.source_in_debug then
      local source, reason = read_optional_string(cursor, "source name")
      if step(reason == nil, reason) then
         proto.source = source or inherited
         origin = proto.source
      end
   end

   local linedefined = ok and cursor:int() or nil
   local lastlinedefined = linedefined and cursor:int() or nil
   if step(lastlinedefined ~= nil, "truncated line range") then
      proto.linedefined = linedefined
      proto.lastlinedefined = lastlinedefined
      proto.line_count = lastlinedefined - linedefined + 1
   end

   -- 5.1 and 5.2 record the upvalue count in the frame description rather than
   -- in a block of its own.
   if ok and layout.frame_upvalues then
      step(cursor:byte() ~= nil, "truncated upvalue count")
   end

   if ok then
      local numparams, is_vararg, maxstack = cursor:byte(), cursor:byte(), cursor:byte()
      if step(numparams ~= nil and is_vararg ~= nil and maxstack ~= nil,
         "truncated frame description") then
         proto.numparams = numparams
         proto.is_vararg = is_vararg
         proto.maxstacksize = maxstack
      end
   end

   -- The instructions are not decoded; only their count is reported, and the
   -- vector is skipped after checking it fits, so a claimed length cannot cost
   -- anything.
   if ok then
      local sizecode = cursor:int()
      if step(sizecode ~= nil, "truncated code count") then
         local width = cursor.sizes.instruction
         if step(sizecode * width <= cursor:remaining(), "code vector past the end of the file")
            and step(cursor:skip(sizecode * width) ~= nil, "truncated code vector") then
            proto.instructions = sizecode
         end
      end
   end

   if ok then
      local sizek = cursor:int()
      if step(sizek ~= nil, "truncated constant count") then
         -- The cap is checked before the loop, not inside it, so a claimed
         -- 200000 constants costs one comparison.
         if step(sizek <= protos.MAX_CONSTANTS, "a prototype claiming " .. sizek .. " constants")
            and step(state.constants_read + sizek <= protos.MAX_CONSTANTS,
               "more than " .. protos.MAX_CONSTANTS .. " constants") then
            for index = 1, sizek do
               local read_ok, reason = read_constant(cursor, proto.constants, index)
               if not step(read_ok, reason) then break end
               state.constants_read = state.constants_read + 1
            end
         end
      end
   end

   -- Field order differs here. 5.1 and 5.2 read the child prototypes straight
   -- after the constants (DumpConstants in 5.1 and 5.2 ends with the child
   -- list); 5.3 and 5.4 read them after the upvalue descriptors.
   if ok and not layout.protos_after_upvalues then
      step(read_protos(cursor, proto, state, depth, origin), "truncated child prototype")
   end

   if ok and layout.upvalue_block then
      local count = cursor:int()
      if step(count ~= nil, "truncated upvalue count") then
         local width = layout.upvalue_block_bytes
         if step(count * width <= cursor:remaining(), "upvalue block past the end of the file")
            and step(cursor:skip(count * width) ~= nil, "truncated upvalue block") then
            proto.upvalue_count = count
         end
      end
   end

   if ok and layout.protos_after_upvalues then
      step(read_protos(cursor, proto, state, depth, origin), "truncated child prototype")
   end

   if ok then
      step(read_debug(cursor, proto, state), "truncated debug information")
   end

   if not ok then
      -- The prototype was registered before it was filled, so a partial one is
      -- dropped rather than reported as a function we understood.
      table.remove(state.protos)
      return false
   end

   return proto
end

-- The nested prototype list. It calls back into walk_function, so the two are
-- declared together and assigned here.
read_protos = function(cursor, proto, state, depth, inherited)
   local count = cursor:int()
   if not count then return halt(state, "truncated child count") end
   if count > protos.MAX_PROTOS then
      return halt(state, "a prototype claiming " .. count .. " children")
   end
   -- Even the smallest child prototype is more than a few bytes, so a count
   -- larger than the file is refused before any loop runs.
   if count * 8 > cursor:remaining() then
      return halt(state, "child count past the end of the file")
   end
   for _ = 1, count do
      local child = walk_function(cursor, state, depth + 1, inherited)
      if not child then return false end
      proto.children = proto.children or {}
      proto.children[#proto.children + 1] = child
   end
   return true
end

--- Walk the prototypes of `bytes` using the layout described by `parsed`.
--
-- Returns {protos = {...}, truncated = bool, reason = string} with `protos`
-- ordered root first, or nil plus a reason when the chunk could not be entered
-- at all. Never raises.
function protos.walk(bytes, parsed)
   if type(bytes) ~= "string" then return nil, "not a byte string" end
   if not parsed then return nil, "no header" end
   if parsed.flavor ~= "lua" then
      return {protos = {}, truncated = false}
   end

   local layout = LAYOUTS[parsed.version]
   if not layout then
      return nil, "no prototype layout for version " .. tostring(parsed.version)
   end

   local sizes = {}
   for key, value in pairs(parsed.sizes) do sizes[key] = value end
   if not sizes.instruction or sizes.instruction < 1 or sizes.instruction > 8 then
      return nil, "unusable instruction width"
   end
   if layout.int == "int32" and (sizes.int ~= 4) then
      -- 5.1 to 5.3 read ints as a native int; anything else means we would be
      -- walking with the wrong stride, so say so rather than misread the file.
      return nil, "expected a 4 byte int, header claims " .. tostring(sizes.int)
   end
   if layout.size == "size_t" and sizes.size_t ~= 4 and sizes.size_t ~= 8 then
      return nil, "unusable size_t width"
   end

   -- luaU_undump reads one byte of upvalue count before the outermost
   -- prototype in 5.3 and 5.4. 5.1 and 5.2 go straight into the prototype.
   local pos = (parsed.end_offset or 0) + 1
   if layout.closure_upvalue_byte then
      if not bytes:byte(pos) then return nil, "truncated before the upvalue count" end
      pos = pos + 1
   end
   if pos > #bytes then return nil, "truncated before the first prototype" end

   local cursor = reader(bytes, pos, sizes, layout)
   local state = {protos = {}, truncated = false, constants_read = 0, protos_read = 0}

   local root = walk_function(cursor, state, 1, nil)

   return {
      protos = state.protos,
      truncated = state.truncated,
      reason = state.reason,
      complete = root ~= nil,
   }
end

return protos
