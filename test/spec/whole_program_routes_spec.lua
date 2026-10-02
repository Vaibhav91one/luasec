-- Whole-program: a call through a route table, `routes[name].handler(req)` or
-- `handlers[name](req)`, where the key is request data and the table literal
-- maps names to handler functions defined in other files.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luasec.api"

local DIR = "test/fixtures/routes"

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

describe("whole-program route tables", function()
   it("follows routes[name].methodHandler(req) into every handler the table names", function()
      local found = sinks(scan({"dispatch.lua", "handlers.lua"}, {whole_program = true}), "709")
      assert_equal(#found, 1, "one 709")
      assert_true(found[1].file:find("handlers.lua", 1, true) ~= nil, "reported in handlers.lua: " .. tostring(found[1].file))
      assert_equal(found[1].line, 6, "at the os.execute line")
   end)

   it("follows handlers[name](req) through a local table of functions", function()
      local found = sinks(scan({"dispatch_flat.lua", "handlers.lua"}, {whole_program = true}), "709")
      assert_equal(#found, 1, "one 709")
   end)

   it("does nothing without --whole-program", function()
      local found = sinks(scan({"dispatch.lua", "handlers.lua"}), "709")
      assert_equal(#found, 0, "no cross-file flow by default")
   end)

   it("does not report a constant argument", function()
      local found = sinks(scan({"dispatch_const.lua", "handlers.lua"}, {whole_program = true}), "709")
      assert_equal(#found, 0, "a constant table carries no taint")
   end)

   it("says so with a 904 when a table has more handlers than the bound", function()
      local report = scan({"dispatch.lua", "handlers.lua"},
         {whole_program = true, whole_program_max_route_targets = 1})
      local hit = false
      for _, finding in ipairs(report) do
         if finding.code == "904" and finding.name == "whole-program route table targets" then hit = true end
      end
      assert_true(hit, "a 904 names the route table bound")
   end)
end)
