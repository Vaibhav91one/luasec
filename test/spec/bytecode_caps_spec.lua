local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_nil = harness.assert_equal, harness.assert_true, assert_nil

local api = require "luadoctor.api"

-- Byte builders for the 5.4 format, from ldump.c dumpSize and loadFunction.
local function varint(value)
   local groups = {}
   repeat groups[#groups + 1] = value % 128 value = math.floor(value / 128) until value == 0
   local out = {}
   for i = #groups, 1, -1 do out[#out + 1] = groups[i] end
   out[#out] = out[#out] + 128
   return out
end

local function concat(lists)
   local out = {}
   for _, list in ipairs(lists) do
      for _, byte in ipairs(list) do out[#out + 1] = string.char(byte) end
   end
   return table.concat(out)
end

local HEADER = concat {
   {0x1B, 0x4C, 0x75, 0x61, 0x54, 0x00, 0x19, 0x93, 0x0D, 0x0A, 0x1A, 0x0A, 4, 8, 8},
   {0x78, 0x56, 0, 0, 0, 0, 0, 0},                  -- LUAC_INT
   {0, 0, 0, 0, 0, 0x28, 0x77, 0x40},               -- LUAC_NUM 370.5
}

-- The smallest a 5.4 prototype can be: no source, no line range, no frame, no
-- code, no constants, no upvalues, no children and empty debug information.
local EMPTY_PROTO = concat {
   varint(0), varint(0), varint(0), {0, 0, 0},
   varint(0), varint(0), varint(0), varint(0),
   varint(0), varint(0), varint(0), varint(0),
}

-- A 5.4 chunk whose main prototype claims `children` child prototypes, each
-- written out in full, so the count is a real count and not a truncation.
local function chunk_with_children(children)
   return HEADER .. string.char(1) .. concat {
      varint(0), varint(0), varint(0), {0, 0, 0},
      varint(0), varint(0), varint(0),
      varint(children),
   } .. EMPTY_PROTO:rep(children) .. concat {varint(0), varint(0), varint(0), varint(0)}
end

local function analyze_bytes(bytes)
   local path = os.tmpname() .. ".luac"
   local handle = assert(io.open(path, "wb"))
   handle:write(bytes)
   handle:close()
   local report = api.analyze({path})
   os.remove(path)
   return report
end

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

describe("bytecode triage: the prototype count cap", function()
   it("walks a chunk with many prototypes when the count is inside the cap", function()
      local report = analyze_bytes(chunk_with_children(200))
      assert_equal(codes(report), "801",
         "200 empty prototypes is a small chunk and should be read fully")
   end)

   it("refuses a claimed child count past the cap before reading any of them", function()
      -- 100001 is past the cap, so the count is rejected on sight: no prototype
      -- is visited and nothing is allocated per child.
      local report = analyze_bytes(chunk_with_children(100001))
      assert_equal(codes(report), "801,805")
      for _, finding in ipairs(report) do
         if finding.code == "805" then
            assert_match(finding.name, "claiming 100001 children")
         end
      end
   end)

   it("stops visiting prototypes at 100000 and says so", function()
      -- Exactly at the cap the count is believed, so the walk starts and then
      -- runs out of budget partway through. The 805 is the finding that says the
      -- chunk was only partly read.
      local start = os.clock()
      local report = analyze_bytes(chunk_with_children(100000))
      local elapsed = os.clock() - start
      assert_equal(codes(report), "801,805")
      for _, finding in ipairs(report) do
         if finding.code == "805" then
            assert_match(finding.name, "more than 100000 prototypes")
         end
      end
      assert_true(elapsed < 10,
         string.format("analyzing a 1.4 MB chunk took %.1fs", elapsed))
   end)
end)
