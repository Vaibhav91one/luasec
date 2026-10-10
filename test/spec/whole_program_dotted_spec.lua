-- Whole-program: a call to a dotted global-table function defined in another
-- file (`gui.a.b.set(x)` with `function gui.a.b.set(cfg)` elsewhere), the shape a
-- CGILua backend uses between a page and its component library.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luadoctor.api"

local DIR = "test/fixtures/dotted"

local function scan(files, opts)
   local paths = {}
   for _, name in ipairs(files) do paths[#paths + 1] = DIR .. "/" .. name end
   opts = opts or {}
   opts.std = opts.std or "cgilua"
   return api.analyze(paths, opts)
end

local function sinks(result, code)
   local out = {}
   for _, finding in ipairs(result.findings or result) do
      if finding.code == code then out[#out + 1] = finding end
   end
   return out
end

describe("whole-program dotted global calls", function()
   it("follows gui.a.b.set(t) into the library and reports the sink there", function()
      local found = sinks(scan({"page.lua", "lib.lua"}, {whole_program = true}), "709")
      assert_equal(#found, 1, "one 709")
      assert_true(found[1].file:find("lib.lua", 1, true) ~= nil, "reported in lib.lua: " .. tostring(found[1].file))
      assert_equal(found[1].line, 4, "at the os.execute line")
   end)

   it("follows a call whose result is assigned (errorFlag = gui.a.b.set(t))", function()
      local found = sinks(scan({"page_assigned.lua", "lib.lua"}, {whole_program = true}), "709")
      assert_equal(#found, 1, "one 709")
   end)

   it("does nothing without --whole-program", function()
      local found = sinks(scan({"page.lua", "lib.lua"}), "709")
      assert_equal(#found, 0, "no cross-file flow by default")
   end)

   it("does not report a constant argument", function()
      local found = sinks(scan({"page_const.lua", "lib.lua"}, {whole_program = true}), "709")
      assert_equal(#found, 0, "a constant table carries no taint")
   end)

   it("declines when two files define the same dotted name", function()
      local found = sinks(scan({"page.lua", "lib.lua", "lib2.lua"}, {whole_program = true}), "709")
      assert_equal(#found, 0, "ambiguous names are never guessed")
   end)

   it("resolves a depth-4 chain", function()
      local found = sinks(scan({"page_deep.lua", "lib_deep.lua"}, {whole_program = true}), "709")
      assert_equal(#found, 1, "gui.a.b.c.d resolves")
   end)

   it("does not resolve through a local that shadows the root", function()
      local found = sinks(scan({"page_shadow.lua", "lib.lua"}, {whole_program = true}), "709")
      assert_equal(#found, 0, "a local gui is not the global")
   end)
end)
