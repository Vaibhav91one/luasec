describe("numeric constants", function()
   it("folds arithmetic over literals", function()
      local api = require "luasec.api"
      -- If folding were broken here, this would look like a dynamic command and
      -- be reported; a fixed command is not a finding.
      local report = api.check_source([[
local function go()
   os.execute("count " .. (1 + 2) .. " items")
end
]])
      assert_equal(#report, 0, "a command built by arithmetic on literals is still constant")
   end)

   it("reports a command that mixes a literal with a computed number", function()
      local api = require "luasec.api"
      local report = api.check_source([[
local function go(n)
   os.execute("count " .. (n + 2) .. " items")
end
]])
      assert_true(#report > 0, "a computed value is not a constant")
   end)
end)
