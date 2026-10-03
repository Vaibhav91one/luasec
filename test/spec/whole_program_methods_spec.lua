-- Whole-program: a method call `obj:m(x)` across files, where obj is a module
-- bound with require or a dotted global table, and m is defined in another file
-- as `function M:m(cfg)` or `M.m = function(self, cfg)`. The receiver is the
-- callee's first formal, as Lua passes it.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luasec.api"

local DIR = "test/fixtures/methods"

local function scan(files, opts)
   local paths = {}
   for _, name in ipairs(files) do paths[#paths + 1] = DIR .. "/" .. name end
   opts = opts or {}
   opts.std = opts.std or "cgilua"
   return api.analyze(paths, opts)
end

local function sinks(result, code)
   local out = {}
   for _, finding in ipairs(result) do
      if finding.code == code then out[#out + 1] = finding end
   end
   return out
end

local function only_in(found, file, line)
   assert_equal(#found, 1, "one 709")
   assert_true(found[1].file:find(file, 1, true) ~= nil, "reported in " .. file .. ": " .. tostring(found[1].file))
   assert_equal(found[1].line, line, "at the os.execute line")
end

describe("whole-program method calls", function()
   it("follows mod:run(req) into function M:run(cfg), the receiver landing on self", function()
      only_in(sinks(scan({"page_mod.lua", "svc.lua"}, {whole_program = true}), "709"), "svc.lua", 4)
   end)

   it("follows mod:go(req) into M.go = function(self, cfg)", function()
      only_in(sinks(scan({"page_mod_dot.lua", "svc.lua"}, {whole_program = true}), "709"), "svc.lua", 8)
   end)

   it("follows the return value of mod:id(x) back into the caller", function()
      only_in(sinks(scan({"page_mod_ret.lua", "svc.lua"}, {whole_program = true}), "709"), "page_mod_ret.lua", 3)
   end)

   it("follows gui.net:set(t) into function gui.net:set(cfg) in another file", function()
      only_in(sinks(scan({"page_global.lua", "lib.lua"}, {whole_program = true}), "709"), "lib.lua", 5)
   end)

   it("follows a method call whose result is assigned", function()
      only_in(sinks(scan({"page_global_assigned.lua", "lib.lua"}, {whole_program = true}), "709"), "lib.lua", 5)
   end)

   it("does nothing without --whole-program", function()
      assert_equal(#sinks(scan({"page_mod.lua", "svc.lua"}), "709"), 0, "no cross-file flow by default")
   end)

   it("does not report a constant argument", function()
      assert_equal(#sinks(scan({"page_mod_const.lua", "svc.lua"}, {whole_program = true}), "709"), 0)
   end)

   it("does not resolve a local receiver that is not the module", function()
      assert_equal(#sinks(scan({"page_local.lua", "svc.lua"}, {whole_program = true}), "709"), 0)
   end)

   it("declines when two files define the same method", function()
      assert_equal(#sinks(scan({"page_global.lua", "lib.lua", "lib_dup.lua"}, {whole_program = true}), "709"), 0,
         "an ambiguous name is never guessed")
   end)

   it("does not resolve through a local that shadows the global root", function()
      assert_equal(#sinks(scan({"page_shadow.lua", "lib.lua"}, {whole_program = true}), "709"), 0)
   end)
end)
