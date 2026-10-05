-- Where a 747 finding's severity comes from: the file's ROLE, not only the
-- literal in it.
--
-- #290 found fifteen findings on the corpus, every one of them at `high` and
-- every one of them a false positive, in two shapes that had nothing to do
-- with each other:
--
--   * a credential-shaped literal in a library's own test suite
--     (`corpus/luasocket/test/urltest.lua` carries `password = "pass?#wd"`
--     eleven times, to prove the URL parser does not cut a password at the
--     first `?` or `#`), and
--   * one in `src/`, which is not a test file at all.
--
-- The direction this must not move is the one the last describe block in this
-- file is about. A fix that stops reporting test fixtures and quietly stops
-- reporting secrets is a net loss, so the strongest assertions here are the
-- ones that stay RED if the scope is widened by one segment too many.
--
-- Everything goes through the public seam, and every case that turns on the
-- path writes a real file, because the path IS the input under test here:
-- `check_source` hands the analyzer a string with no file behind it, and no
-- path is not evidence that the file is a test file.

local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true
local scratch_dir = harness.scratch_dir

local api = require "luasec.api"

-- Every 747 in a report, in report order.
local function with_code(report, code)
   local out = {}
   for _, finding in ipairs(report) do
      if finding.code == code then out[#out + 1] = finding end
   end
   return out
end

local function write(path, text)
   local handle = assert(io.open(path, "w"))
   handle:write(text)
   handle:close()
end

local function drop(dir)
   os.execute("rm -rf " .. string.format("%q", dir))
end

--- Write `source` at `<tmp>/<relative>` and analyze it as that path.
--
-- `relative` carries the directory names, because the directory names are what
-- is under test. `mkdir -p` so the caller can ask for `tests/`, `spec/` and
-- `t/` without building the tree itself.
local function analyze_at(source, relative)
   local dir = scratch_dir("secrets_scope")
   local path = dir .. "/" .. relative
   local parent = path:match("^(.*)/[^/]+$")
   if parent then os.execute("mkdir -p " .. string.format("%q", parent)) end
   write(path, source)
   local report = api.analyze({path})
   drop(dir)
   return report
end

-- The severity of the one 747 in a report, or nil when there is none. Reading
-- the severity and not the count on purpose: the count is what every
-- over-broad fix preserves, and the severity is what it moves.
local function severity_of(report)
   local found = with_code(report, "747")
   assert_equal(#found, 1, "expected exactly one 747, got " .. #found)
   return found[1].severity
end

-- A credential in a table the author is parsing, not one anyone logs in with.
local URL_FIXTURE = [[
local parsed = {
   url = "scheme://user:pass?#wd@host:port/path",
   user = "user",
   password = "pass?#wd",
}
return parsed
]]

-- A credential somebody chose, in a file that ships.
local SHIPPED_PASSWORD = [[
local telnet_password = "R00tPassw0rd-2024"
return telnet_password
]]

-- The default an anonymous-FTP client sends when the caller named no password.
local ANONYMOUS_FTP = [[
local ftp = {}
ftp.USER = "ftp"
ftp.PASSWORD = "anonymous@anonymous.org"
return ftp
]]

describe("a credential in a test file", function()
   it("is reported at low, because a fixture is not an exposure", function()
      local report = analyze_at(URL_FIXTURE, "tests/url_parser.lua")
      assert_equal(severity_of(report), "low",
         "a credential-shaped literal in a test suite is a parse fixture")
   end)

   it("is still a finding, because it is still a credential-shaped literal", function()
      -- The demotion is a statement about exposure, not about detection.
      -- Dropping the finding instead would take with it any real secret a
      -- developer pastes into a test file while debugging, and that is the
      -- direction this may not fail in.
      local report = analyze_at(SHIPPED_PASSWORD, "tests/telnet_login.lua")
      assert_equal(severity_of(report), "low")
   end)

   it("does not depend on which name the test suite's directory carries", function()
      for _, directory in ipairs{"test", "tests", "spec", "specs"} do
         local report = analyze_at(SHIPPED_PASSWORD, directory .. "/telnet_login.lua")
         assert_equal(severity_of(report), "low",
            directory .. "/ is a test suite, so the fixture inside it is not shipped")
      end
   end)

   it("is not what a one-letter directory is taken to mean", function()
      -- `t/` is the OpenResty and Test::Nginx convention, so it is the obvious
      -- fifth entry, and it is not in the vocabulary. macOS hands every process
      -- a scratch directory at `/var/folders/<a>/<b>/T/`, so a whole-segment
      -- match on `t` lowers the severity of every finding in every temporary
      -- file this tool is pointed at - including a firmware image a CI job
      -- unpacked. The corpus is what the entry would have bought: the five
      -- `.lua` files under the OpenResty `t/` directories hold no
      -- credential-shaped literal, so here it hides a credential class and
      -- buys nothing.
      local report = analyze_at(SHIPPED_PASSWORD, "t/telnet_login.lua")
      assert_equal(severity_of(report), "high",
         "a one-character directory is not evidence of a test suite")
   end)

   it("does not depend on a name that merely contains one", function()
      for _, directory in ipairs{"contest", "latest", "spectrum", "manifest"} do
         local report = analyze_at(SHIPPED_PASSWORD, directory .. "/telnet_login.lua")
         assert_equal(severity_of(report), "high",
            directory .. "/ is not a test suite, however it is spelled")
      end
   end)

   it("does not depend on the test suite's directory being the top-level one", function()
      local report = analyze_at(SHIPPED_PASSWORD, "luasocket/test/urltest.lua")
      assert_equal(severity_of(report), "low",
         "the corpus shape: a library's own test file, two segments down")
   end)

   it("is reported at low for a file whose own name says it is a test", function()
      for _, name in ipairs{"telnet_login_test.lua", "test_telnet_login.lua",
                            "telnet_login_spec.lua", "spec_telnet_login.lua"} do
         local report = analyze_at(SHIPPED_PASSWORD, "app/" .. name)
         assert_equal(severity_of(report), "low",
            name .. " is a test file wherever it sits")
      end
   end)

   it("still reports a private key block in a test file at high", function()
      -- The one shape the test-file demotion does not reach, and the reason is
      -- not that a key is common in a test tree - it is that the demotion
      -- lowers findings whose EVIDENCE is a credential-named binding, and a
      -- key block's evidence is the block itself, whatever name it is filed
      -- under. A key is not a fixture shape; people paste real development
      -- keys into test directories, and the cost of reporting one is a line
      -- while the cost of dropping one is a credential in the repository.
      local report = analyze_at([[
local pem = [==[
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtESTKEYMATERIALONLY0123456789abcdefghijklmnopqrstuvwx
yz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv
0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz
0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwx
yz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv
-----END RSA PRIVATE KEY-----
]==]
return pem
]], "tests/embedded_key.lua")
      assert_equal(severity_of(report), "high",
         "a private key in a test tree keeps the severity of the finding")
   end)
end)

describe("a real credential in code that ships", function()
   it("is reported at high, which is the whole finding and may not move", function()
      local report = analyze_at(SHIPPED_PASSWORD, "src/telnet_login.lua")
      assert_equal(severity_of(report), "high",
         "a shipped admin password is what 747 exists for")
   end)

   it("is reported at high when no path was given at all", function()
      -- `check_source` is a caller with no file behind the string, and a
      -- missing path is not evidence of a test file. The conservative
      -- default has to be the one that reports.
      local report = api.check_source(SHIPPED_PASSWORD)
      assert_equal(severity_of(report), "high",
         "with no path to classify, the finding stands at its registered severity")
   end)

   it("is reported at high in a table that is plainly configuration", function()
      -- The placement route the issue offers - "a literal in a field named
      -- `password` inside a table that is clearly a fixture" - is NOT taken,
      -- and this is why. This table is indistinguishable, to anything the
      -- rule can read, from a parse fixture: a name, a host, a user and a
      -- password. It is how firmware writes an FTP connection configuration,
      -- and suppressing it is the direction that may not move.
      local report = analyze_at([[
local site = {
   scheme = "ftp",
   host = "mirror.example.com",
   user = "svc-mirror",
   password = "Fr7-quiet-harbour-92",
}
return site
]], "src/site_config.lua")
      assert_equal(severity_of(report), "high",
         "placement cannot tell a fixture from a configuration; the path can")
   end)

   it("is reported at high for a token whose value happens to look like an address", function()
      -- The anonymous-login shape is a rule about the PASSWORD field, not
      -- about every value with an `@` in it.
      local report = analyze_at([[
local api_token = "svc-account@corp.acme-internal.net"
return api_token
]], "src/api_client.lua")
      assert_equal(severity_of(report), "high",
         "a token that looks like an address is still a token")
   end)
end)

describe("the anonymous-FTP login identity", function()
   it("is reported at low rather than high", function()
      local report = analyze_at(ANONYMOUS_FTP, "src/ftp.lua")
      assert_equal(severity_of(report), "low",
         "the default an anonymous login sends is not a credential anyone chose")
   end)

   it("is recognised by its shape, so no address the client picks is missed", function()
      -- Every FTP client that has ever been written picks a different one, and
      -- a table inside luasec would have to be given every one of them. The
      -- shape is what the convention is: an identity the server logs, sent in
      -- place of a password somebody chose.
      for _, value in ipairs{"anonymous@", "anonymous@anonymous.org", "ftp@ftp.acme-internal.net"} do
         local report = analyze_at("local PASSWORD = " .. string.format("%q", value) .. "\n"
            .. "return PASSWORD\n", "src/ftp_client.lua")
         assert_equal(severity_of(report), "low",
            value .. " is the anonymous-login shape whatever address it carries")
      end
   end)

   it("is still a finding", function()
      -- Low, not absent. The value is a credential-shaped literal and the
      -- rule cannot prove it is a convention rather than a choice, so it stays
      -- in the report where `--only 747` can find it.
      local report = analyze_at(ANONYMOUS_FTP, "src/ftp.lua")
      assert_true(with_code(report, "747")[1] ~= nil,
         "the finding survives at low, so nothing is quietly swallowed")
   end)

   it("does not reach a password whose domain is not one", function()
      local report = analyze_at([[
local admin_password = "root@10.0.0.5"
return admin_password
]], "src/admin_login.lua")
      assert_equal(severity_of(report), "high",
         "an IPv4 literal is a host, not an anonymous-login identity")
   end)

   it("does not reach a password that merely contains an at sign", function()
      local report = analyze_at([[
local db_password = "p@ssw0rd-fragments"
return db_password
]], "src/db_login.lua")
      assert_equal(severity_of(report), "high",
         "an `@` in the middle of a password is not an address")
   end)
end)