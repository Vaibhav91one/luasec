-- A declared source is untrusted input whichever way it is written.
--
-- `platform_api.match_source` had exactly one call site, inside `taint_of_call`,
-- so a dotted-path source resolved only in call position: `ngx.req.get_uri_arg("q")`
-- was untrusted data and `ngx.var.http_user_agent` read into a local was not. The
-- same source declaration, in the same file, meant two different things.
--
-- These specs cover the value position, the profile declarations that were dead
-- there, and - the case that matters most - the field reads that are not sources
-- and must stay quiet.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true, assert_nil, assert_equal = harness.assert_true, harness.assert_nil, harness.assert_equal

local api = require "luasec.api"

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

local function of(report, code)
   for _, finding in ipairs(report) do
      if finding.code == code then return finding end
   end
end

describe("sources read as values", function()
   it("reports an nginx variable read into a local and reaching a command as untrusted data", function()
      local report = api.check_source([[
local ua = ngx.var.http_user_agent
os.execute("logger -t web " .. ua)
]], {std = "openresty"})
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_equal(finding.source, "ngx.var")
   end)

   it("does not report a global field read that no profile declares as a source", function()
      -- The shape is identical to `ngx.var.http_user_agent` -- an Index on a
      -- bare global, read into a local, concatenated into a command. What keeps
      -- it out of the report is that no source declaration matches the resolved
      -- path, so a value-position check that keyed on the node's shape rather
      -- than on the registry would fail here.
      local report = api.check_source([[
local server_name = config.http.server_name
os.execute("logger -t web " .. server_name)
]], {std = "openresty"})
      assert_nil(of(report, "709"), "an undeclared global field read is not untrusted data")
      assert_true(of(report, "701") ~= nil, "the command is still reported as a shape, got " .. codes(report))
   end)

   it("does not report a field read on the same global that no source declares", function()
      -- `ngx` roots a declared source and an undeclared one in the same file, so
      -- only the declaration separates them. `ngx.var.*` is a source; nothing
      -- declares `ngx.nginx_version`, so reading it must stay quiet.
      local report = api.check_source([[
local version = ngx.nginx_version
local ua = ngx.var.http_user_agent
os.execute("logger -t web " .. version .. " " .. ua)
]], {std = "openresty"})
      local finding = of(report, "709")
      assert_true(finding ~= nil, "the declared source still fires, got " .. codes(report))
      assert_equal(finding.source, "ngx.var",
         "only the declared source may be named")
   end)

   it("resolves a dotted-path source read as a value in every profile, not only openresty", function()
      -- The defect was never `ngx.var`'s: `match_source` was reached from one
      -- call site, so every dotted-path source declaration in the registry was
      -- dead in value position. One example per profile, because a fix that
      -- matched only the symbol in the issue would pass the first one alone.
      local cases = {
         {std = "openwrt", source = "uci.get.hello", expected = "uci.get", code = [[
local host = uci.get.hello
os.execute(host)
]]},
         {std = "hisi", source = "net.hostname", expected = "net", code = [[
local host = net.hostname
os.execute(host)
]]},
         {std = "cgilua", source = "cgi.form.action", expected = "cgi", code = [[
local action = cgi.form.action
os.execute(action)
]]},
         {std = "openresty", source = "ngx.req.get_headers().host", expected = "ngx.req.get_headers", code = [[
os.execute(ngx.req.get_headers().host)
]]},
      }
      for _, case in ipairs(cases) do
         local report = api.check_source(case.code, {std = case.std})
         local finding = of(report, "709")
         assert_true(finding ~= nil,
            case.source .. " read as a value under --std " .. case.std .. " is untrusted data, got " .. codes(report))
         assert_equal(finding.source, case.expected, case.source .. " names the declaration it matched")
      end
   end)

   it("reports a field read off the query-args table the plural getter returns", function()
      -- `get_uri_args` is a different function from `get_uri_arg`: the singular
      -- one was declared and the plural one was not, so the way the documented
      -- OpenResty idiom actually reads its input was silent. The field read is
      -- a second hop: `a` is the table, `a.q` is one column of it.
      local report = api.check_source([[
local args = ngx.req.get_uri_args()
os.execute("logger -t web " .. args.q)
]], {std = "openresty"})
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_equal(finding.source, "ngx.req.get_uri_args")
   end)

   it("does not claim an nginx variable is proven attacker data", function()
      -- `ngx.var.*` is a blanket pattern over every nginx variable, and not
      -- every one of them is attacker-influenced: `$pid` and `$hostname` are
      -- the server's, and `$http_user_agent` usually reaches nginx through a
      -- proxy that can rewrite it. `certain` is the level this engine uses for
      -- data it read out of the request itself -- luci.http.formvalue, the
      -- singular get_uri_arg -- and an nginx variable is not that. It is
      -- influenced, which is the same claim the LuCI dispatcher entry point
      -- makes about data this tool infers rather than reads.
      local report = api.check_source([[
local ua = ngx.var.http_user_agent
os.execute("logger -t web " .. ua)
]], {std = "openresty"})
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_equal(finding.confidence, "medium",
         "an nginx variable is attacker-influenced, not proven")
   end)

   it("keeps a source that reads the request at certain", function()
      -- The level change is scoped to the inferred source. formvalue and the
      -- singular get_uri_arg name a value out of the request, which is a
      -- stronger claim than anything this issue adds.
      local report = api.check_source([[
local q = ngx.req.get_uri_arg("q")
os.execute(q)
]], {std = "openresty"})
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_equal(finding.confidence, "certain")
   end)
end)