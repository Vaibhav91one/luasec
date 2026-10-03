-- A declared validator used as a guard before a command lowers the finding's
-- confidence and names the guard, rather than dropping it: the guard's strength
-- is left for a reviewer or an AI agent to confirm.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luasec.api"

local function at(report, code)
   for _, f in ipairs(report) do if f.code == code then return f end end
end

local GUARDED = [[
local ip = cgi["ip"]
if validations.is_ipv4_address(ip) or validations.is_fqdn_address(ip) then
   os.execute("ping " .. ip)
end
]]
local UNGUARDED = [[
os.execute("ping " .. cgi["ip"])
]]

describe("validator guard", function()
   it("keeps a guarded flow but lowers its confidence and names the guard", function()
      local guarded = at(api.check_source(GUARDED, {std = "cgilua"}), "709")
      local plain = at(api.check_source(UNGUARDED, {std = "cgilua"}), "709")
      assert_true(guarded ~= nil, "a guarded flow is still reported")
      assert_match(guarded.message, "guarded by validations.is_fqdn_address")
      assert_equal(guarded.guarded_by, "validations.is_fqdn_address")
      -- the unguarded flow is at least as confident as the guarded one
      local rank = {certain = 4, high = 3, medium = 2, low = 1}
      assert_true(rank[guarded.confidence] < rank[plain.confidence],
         "guarded " .. guarded.confidence .. " must be below unguarded " .. plain.confidence)
   end)

   it("does not mark a flow that no validator guards", function()
      local f = at(api.check_source(UNGUARDED, {std = "cgilua"}), "709")
      assert_true(f.guarded_by == nil)
      assert_true(not f.message:find("guarded by", 1, true))
   end)
end)
