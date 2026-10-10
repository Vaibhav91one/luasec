local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luadoctor.api"

-- Fixtures are read from disk and analyzed as source, so the handler a vendor
-- would hand us is the handler the spec reasons about.
local function fixture(name, opts)
   local handle = assert(io.open("test/fixtures/openresty/" .. name, "r"))
   local source = handle:read("*a")
   handle:close()
   return api.check_source(source, opts)
end

local function with_code(report, code)
   local out = {}
   for _, finding in ipairs(report) do
      if finding.code == code then out[#out + 1] = finding end
   end
   return out
end

describe("openresty profile", function()
   it("reports a request parameter copied into a response header as 730", function()
      local report = fixture("resp_header_tainted.lua", {std = "openresty"})
      local found = with_code(report, "730")
      assert_equal(#found, 1, "one response header write, so one 730: "
         .. #report .. " findings, " .. #found .. " of them 730")
      assert_equal(found[1].sink, "ngx.resp.set_header")
      assert_equal(found[1].source, "ngx.req.get_uri_arg")
      assert_equal(found[1].severity, "high")
      assert_equal(found[1].cwe, "CWE-93")
   end)

   it("reports a request parameter copied into a request header as 730", function()
      local report = fixture("req_header_tainted.lua", {std = "openresty"})
      local found = with_code(report, "730")
      assert_equal(#found, 1, "one request header write, so one 730: "
         .. #report .. " findings, " .. #found .. " of them 730")
      assert_equal(found[1].sink, "ngx.req.set_header")
      assert_equal(found[1].source, "ngx.req.get_uri_arg")
   end)

   it("reports a request parameter written into a rewritten URI as 730", function()
      local report = fixture("uri_tainted.lua", {std = "openresty"})
      local found = with_code(report, "730")
      assert_equal(#found, 1, "one URI write, so one 730: "
         .. #report .. " findings, " .. #found .. " of them 730")
      assert_equal(found[1].sink, "ngx.req.set_uri")
   end)

   it("reports a request body written into a subrequest as 731, not as a header write", function()
      local report = fixture("subrequest_tainted.lua", {std = "openresty"})
      local found = with_code(report, "731")
      assert_equal(#found, 1, "one subrequest, so one 731: "
         .. #report .. " findings, " .. #found .. " of them 731")
      assert_equal(found[1].sink, "ngx.location.capture")
      assert_equal(found[1].source, "ngx.req.get_post_args")
      assert_equal(found[1].severity, "high")
      assert_equal(found[1].cwe, "CWE-444")
      assert_equal(#with_code(report, "730"), 0,
         "a subrequest body is request smuggling, not CRLF injection")
   end)

   it("reports a request parameter written into a subrequest header as 731", function()
      local report = fixture("subrequest_header_tainted.lua", {std = "openresty"})
      local found = with_code(report, "731")
      assert_equal(#found, 1, "one subrequest, so one 731: "
         .. #report .. " findings, " .. #found .. " of them 731")
      assert_equal(found[1].sink, "ngx.location.capture")
      assert_equal(found[1].source, "ngx.req.get_uri_arg")
   end)

   it("reports a tainted redirect target as a header write, not as command execution", function()
      local report = fixture("redirect_tainted.lua", {std = "openresty"})
      assert_equal(#with_code(report, "709"), 0,
         "ngx.redirect runs no command, so it must not be reported as 709")
      local found = with_code(report, "730")
      assert_equal(#found, 1, "one redirect, so one 730: "
         .. #report .. " findings, " .. #found .. " of them 730")
      assert_equal(found[1].sink, "ngx.redirect")
   end)

   it("says nothing about a header or subrequest write whose value is a constant local", function()
      local report = fixture("header_writes_literal.lua", {std = "openresty"})
      assert_equal(#report, 0,
         "a non-constant argument is the normal case for these APIs; only proven "
         .. "request data is a finding: " .. #report .. " findings")
   end)

   it("leaves the same header write silent without the std", function()
      local report = fixture("resp_header_tainted.lua")
      assert_equal(#with_code(report, "730"), 0,
         "no 730 without the std, so the sink belongs to the profile")
   end)

   it("reports a request parameter written into the query string as 730", function()
      local report = fixture("uri_args_tainted.lua", {std = "openresty"})
      local found = with_code(report, "730")
      assert_equal(#found, 1, "one query-string write, so one 730: "
         .. #report .. " findings, " .. #found .. " of them 730")
      assert_equal(found[1].sink, "ngx.req.set_uri_args")
   end)

   it("reports a request header concatenated into a response header value as 730", function()
      local report = fixture("resp_header_concatenated.lua", {std = "openresty"})
      local found = with_code(report, "730")
      assert_equal(#found, 1, "one header write, so one 730: "
         .. #report .. " findings, " .. #found .. " of them 730")
      assert_equal(found[1].source, "ngx.req.get_headers")
   end)

   -- ngx.header[k] = v is an assignment to an index target, not a call, so no
   -- call-pattern sink can match it. The value position -- v -- is where
   -- untrusted data reaches the header message, and it is the same defect 730
   -- already names for the call form.

   it("reports a request parameter assigned into a response header as 730", function()
      local report = fixture("header_assignment_tainted.lua", {std = "openresty"})
      local found = with_code(report, "730")
      assert_equal(#found, 1, "one header assignment, so one 730: "
         .. #report .. " findings, " .. #found .. " of them 730")
      assert_equal(found[1].sink, "ngx.header")
      assert_equal(found[1].source, "ngx.req.get_uri_arg")
      -- The assignment is influenced exactly as the call form is, so it carries
      -- the same confidence and severity rather than a guess.
      assert_equal(found[1].confidence, "certain")
      assert_equal(found[1].severity, "high")
      assert_equal(found[1].cwe, "CWE-93")
   end)

   it("says nothing when a constant is assigned into ngx.header", function()
      local report = fixture("header_assignment_literal.lua", {std = "openresty"})
      assert_equal(#report, 0,
         "a constant header value is the normal case; only proven request data "
         .. "is a finding: " .. #report .. " findings")
   end)

   it("reports both the call form and the assignment form of one header write", function()
      local report = fixture("header_both_forms.lua", {std = "openresty"})
      local found = with_code(report, "730")
      -- Neither shape may suppress the other: #227's call sink and this
      -- assignment sink are independent matchers on independent positions.
      assert_equal(#found, 2, "one call form plus one assignment form, so two 730: "
         .. #report .. " findings, " .. #found .. " of them 730")
      local sinks = {}
      for _, entry in ipairs(found) do sinks[entry.sink] = true end
      assert_true(sinks["ngx.resp.set_header"] == true,
         "the call form still fires alongside the assignment form")
      assert_true(sinks["ngx.header"] == true,
         "the assignment form fires alongside the call form")
   end)

   it("leaves the same header assignment silent without the std", function()
      local report = fixture("header_assignment_tainted.lua")
      assert_equal(#with_code(report, "730"), 0,
         "no 730 without the std, so the assignment sink belongs to the profile")
   end)

   -- A tainted KEY is a different question from a tainted value and is
   -- explicitly out of scope rather than silently uncovered: the value position
   -- is the sink, because the key is the attacker choosing WHICH header while
   -- the program still chooses the bytes in it. These two specs pin that
   -- written decision so it cannot drift into looking covered.

   it("says nothing about a tainted key assigned to a constant header value", function()
      local report = fixture("header_assignment_tainted_key.lua", {std = "openresty"})
      assert_equal(#report, 0,
         "a tainted key with a constant value chooses the header name, not the "
         .. "header bytes, so it is documented out of scope: " .. #report .. " findings")
   end)

   it("still reports the value when both the key and the value of ngx.header are tainted", function()
      local report = fixture("header_assignment_tainted_key_both.lua", {std = "openresty"})
      local found = with_code(report, "730")
      assert_equal(#found, 1,
         "the value position is the sink and it is tainted: " .. #report
         .. " findings, " .. #found .. " of them 730")
      assert_equal(found[1].source, "ngx.req.get_uri_arg")
   end)
   it("reports a request parameter used as the pattern of ngx.re.find or ngx.re.gsub as 728 and nothing else (#310)", function()
      -- ngx.re.* executes nothing: the engine's default 709 'command execution' (certain) used to
      -- ride along with the 728 because the std also declared these as taint sinks.
      for _, call in ipairs({
         'ngx.re.find(ngx.var.uri, pattern, "jo")',
         'ngx.re.gsub(ngx.var.uri, pattern, "x", "jo")',
      }) do
         local report = api.check_source("local pattern = ngx.req.get_uri_args().q\n" .. call .. "\n",
            {std = "openresty"})
         local codes = {}
         for _, finding in ipairs(report) do codes[#codes + 1] = finding.code end
         table.sort(codes)
         assert_equal(table.concat(codes, ","), "728", call .. " reported " .. table.concat(codes, ","))
      end
   end)
end)