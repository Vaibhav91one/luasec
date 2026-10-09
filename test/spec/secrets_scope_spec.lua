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

-- The repository root, for the specs below that need a path a symlink or a
-- subprocess can be built from. `harness.cli` runs `./bin/luasec`, which stops
-- resolving the moment the command changes directory first.
local function repo_root()
   local pipe = assert(io.popen("pwd"))
   local root = pipe:read("*l")
   pipe:close()
   return root
end

-- The severity of the one 747 in a JSON report on disk, or nil when there is
-- none. The finding's presence is read as well as its severity, because a rule
-- that stopped reporting is not a rule that stopped being wrong.
local function severity_in_json(path)
   local handle = assert(io.open(path, "r"))
   local text = handle:read("*a")
   handle:close()
   return text:match('"id"%s*:%s*"747".-"severity"%s*:%s*"(%a+)"')
end

--- Run the CLI from `dir` over a RELATIVE path, with `$PWD` naming nothing.
--
-- `bin/luasec` cannot be used to do this. Its `#!/bin/sh` sets `PWD` to the real
-- working directory at startup, as every POSIX shell does, so a doctored value
-- handed to it has been overwritten before any Lua runs - which is why this
-- repeats the two lines `bin/luasec` execs rather than calling it. It is the
-- documented CLI entry point either way; what changes is only that the
-- interpreter is reached without a shell in between.
local function cli_with_unreadable_pwd(dir, args)
   local root = repo_root()
   local interpreter = root .. "/build/lua-5.4.9/src/lua"
   local report = dir .. "/report.json"
   local command = ("cd %s && PWD=/nonexistent-luasec-pwd exec %s -e %s %s %s > %s 2>&1")
      :format(string.format("%q", dir), string.format("%q", interpreter),
              string.format("%q", "package.path='" .. root
                 .. "/src/?.lua;" .. root .. "/src/?/init.lua;"
                 .. root .. "/vendor/?.lua;" .. root .. "/vendor/?/init.lua;'..package.path"),
              string.format("%q", root .. "/src/luasec/main.lua"),
              table.concat(args, " "), string.format("%q", report))
   os.execute(command)
   return severity_in_json(report)
end

--- Write `source` at `<tree>/<relative>` and analyze it as that path.
--
-- `relative` carries the directory names, because the directory names are what
-- is under test. `mkdir -p` so the caller can ask for `tests/`, `spec/` and
-- `t/` without building the tree itself.
local function plant(tree, source, relative)
   local path = tree .. "/" .. relative
   local parent = path:match("^(.*)/[^/]+$")
   if parent then os.execute("mkdir -p " .. string.format("%q", parent)) end
   write(path, source)
   return path
end

-- A source tree, which is NOT `harness.scratch_dir`.
--
-- That helper hands out `$TMPDIR/luasec_...`, which on macOS is under
-- `/var/folders/<a>/<b>/T/` - the very directory the rule under test excludes.
-- Building the tree in the repository's own (gitignored) build directory keeps
-- it on the other side of that distinction, which is the whole of what these
-- specs are about: `t/` in a source tree is a test suite, `t/` in a scratch
-- directory is a directory the operating system named.
local SOURCE_TREE = "build/spec-scope"

-- A symlink at `<SOURCE_TREE>/<relative>` naming `target`.
--
-- `ln -s` and not a copy, because the question here is what the kernel resolves
-- a path to, and a copy is not a link: it would answer a different question.
local function link_at(relative, target)
   local path = SOURCE_TREE .. "/" .. relative
   os.remove(path)
   os.execute(("mkdir -p %s"):format(string.format("%q", SOURCE_TREE)))
   local ok = os.execute(("ln -s %s %s"):format(string.format("%q", target),
                                                string.format("%q", path)))
   assert(ok, "ln -s failed for " .. path)
   return path
end

local function analyze_at(source, relative)
   local path = plant(SOURCE_TREE, source, relative)
   local report = api.analyze({path})
   drop(SOURCE_TREE)
   return report
end

-- The same file, built under a scratch directory. Which directory that is
-- depends on the host: `$TMPDIR` when it is set (`/var/folders/<a>/<b>/T/` on
-- macOS) and `/tmp` otherwise. Both are the temporary roots the rule excludes,
-- which is what makes this the control for `analyze_at`.
local function analyze_in_scratch(source, relative)
   local dir = scratch_dir("secrets_scope")
   local path = plant(dir, source, relative)
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

   it("is what a one-letter directory in a source tree is taken to mean", function()
      -- `t/` is the OpenResty and Test::Nginx convention, it is a real and
      -- common layout, and it is in this vocabulary because of that.
      --
      -- #290 left it out on a measurement - the five `.lua` files under the
      -- OpenResty `t/` directories in the corpus hold no credential-shaped
      -- literal, so on this corpus the entry buys nothing - and that is
      -- corpus-fitting for a rule that ships to scan trees nobody here has
      -- cloned. What it also did was hide a real credential class in every
      -- other OpenResty checkout. The macOS scratch directory is a genuine
      -- bug and it is answered by excluding temp roots, which is the spec
      -- two below.
      local report = analyze_at(SHIPPED_PASSWORD, "t/telnet_login.lua")
      assert_equal(severity_of(report), "low",
         "`t/` is how OpenResty and Test::Nginx spell a test suite")
   end)

   it("is not a test directory anywhere under a scratch root, whatever it is called", function()
      -- The other side of the same distinction. `$TMPDIR` on macOS is
      -- `/var/folders/<a>/<b>/T/`, so the operating system names a directory
      -- `T` and a one-letter vocabulary entry would lower the severity of
      -- every finding in every scratch file this tool is pointed at -
      -- including a firmware image a CI job unpacked.
      --
      -- The exclusion is about the ROOT, not about the one-letter name, so
      -- the ordinary spellings are in here too: a fix that excluded only
      -- `t/` would pass the first case and leave the rest of the hole.
      for _, relative in ipairs{ "whatever/t/telnet_login.lua",
                                 "whatever/tests/telnet_login.lua",
                                 "app/test_telnet_login_spec.lua" } do
         local report = analyze_in_scratch(SHIPPED_PASSWORD, relative)
         assert_equal(severity_of(report), "high",
            relative .. " is under a temporary root, which is not a source tree")
      end
   end)

   it("is not a test directory through a link that points into a scratch root", function()
      -- The one hole the lexical reading of the path cannot see.
      --
      -- `absolute()` folds `..` and unifies separators, which is exactly what
      -- stops `/tmp/../etc/t/x.lua` from being read as a file in `/tmp` - and
      -- none of that touches a LINK. `build/link -> $TMPDIR` spells a file in
      -- `build/` and is scratch space, and asked from the spelling alone the
      -- exclusion said `t/` was a test suite. Same defect class as the `..`
      -- case, and it under-excludes for the same reason: the answer was read off
      -- a string that does not say where the file is.
      --
      -- TWO links, one spelling, differing only in where they point, because a
      -- single case does not separate the two things a fix here could be. Answer
      -- `high` for both and the rule has decided a link is not a test suite,
      -- which is not what it is supposed to have decided. Answer `low` for both
      -- and nothing was closed. Only the pair says which.
      local scratch = scratch_dir("secrets_scope_link")
      drop(SOURCE_TREE)
      plant(scratch, SHIPPED_PASSWORD, "t/telnet_login.lua")
      plant(SOURCE_TREE, SHIPPED_PASSWORD, "elsewhere/t/telnet_login.lua")
      -- ABSOLUTE targets, because a link's target is read relative to the
      -- directory holding the link, and `build/spec-scope/elsewhere` spelled
      -- relative to `build/spec-scope/` is `build/spec-scope/build/spec-scope/…`
      -- - a link to nothing, which is a third case this spec is not about.
      local root = repo_root()
      link_at("into-scratch", scratch)
      link_at("into-source", root .. "/" .. SOURCE_TREE .. "/elsewhere")

      local function severity_through(link)
         local report = api.analyze({SOURCE_TREE .. "/" .. link .. "/t/telnet_login.lua"})
         return severity_of(report)
      end

      assert_equal(severity_through("into-scratch"), "high",
         "the file is scratch space; `t/` there is a directory the system named")
      assert_equal(severity_through("into-source"), "low",
         "the same spelling into a source tree is a test suite, link or not")

      drop(SOURCE_TREE)
      drop(scratch)
   end)

   it("reads a path it has no anchor for from its own spelling, and still reports it", function()
      -- The fallback, on the other side of resolution. When `$PWD` names
      -- nothing, `cwd()` declines and a RELATIVE path stays relative, so there
      -- is no anchor - and resolution is not consulted, the same refusal the
      -- prefix test already makes, applied to both halves rather than one.
      --
      -- This corner under-excludes and did before: `t/` under a scratch root
      -- reads as a test suite here and as scratch space one spec above, purely
      -- because the spelling that arrived here carried no anchor to check. It is
      -- pinned rather than closed because closing it means asking the process for
      -- a working directory the prefix test also declined to guess at, and a
      -- guessed one is how a finding gets demoted on the say-so of a directory
      -- nobody read. The finding is in the report either way, and that is the
      -- half that may not fail.
      local scratch = scratch_dir("secrets_scope_pwd")
      plant(scratch, SHIPPED_PASSWORD, "t/telnet_login.lua")
      plant(scratch, SHIPPED_PASSWORD, "pkg/telnet_login.lua")

      assert_equal(cli_with_unreadable_pwd(scratch,
            {"--format", "json", "--only", "747", "t/telnet_login.lua"}), "low",
         "the spelling says `t/` and there is no anchor that could say otherwise")
      assert_equal(cli_with_unreadable_pwd(scratch,
            {"--format", "json", "--only", "747", "pkg/telnet_login.lua"}), "high",
         "with no anchor there is no test directory in `pkg/`, so the severity stands")

      drop(scratch)
   end)

   it("keeps reading the spelling when a path cannot be resolved at all", function()
      -- The other fallback, and the one that is reachable on every host: a link
      -- that names nothing. `cd -P` fails on it, there is no resolved path to
      -- test, and the answer is the spelling's - which for `t/` is a test suite,
      -- because that is all the evidence there is.
      --
      -- It is the loud end of the rule: a dangling link is not a scratch root,
      -- and a finding that cannot be placed is not demoted on the strength of
      -- where it might have been.
      drop(SOURCE_TREE)
      os.execute(("mkdir -p %s"):format(string.format("%q", SOURCE_TREE)))
      os.execute(("ln -s %s %s"):format(string.format("%q", SOURCE_TREE .. "/nothing-here"),
                                        string.format("%q", SOURCE_TREE .. "/dangling")))
      local report = api.analyze({SOURCE_TREE .. "/dangling/t/telnet_login.lua"})
      -- The file was never written, so there is no finding to read a severity
      -- from: the point is that nothing was reported as unreadable-silence, and
      -- the report says so out loud rather than coming back empty.
      assert_true(#with_code(report, "747") == 0 and #report > 0,
         "a path that cannot be resolved is reported unreadable, not skipped")
      drop(SOURCE_TREE)
   end)

   it("follows $TMPDIR when it is set somewhere the rule cannot know", function()
      -- `$TMPDIR` names a directory the operating system chose, and the
      -- caller may have set it to anything. It is honoured rather than
      -- assumed, and the control is the same file read with the ambient
      -- `$TMPDIR`: the only thing that changed is the variable.
      local dir = "build/spec-scope-tmpdir"
      drop(dir)
      local path = plant(dir, SHIPPED_PASSWORD, "pkg/t/telnet_login.lua")

      local function severity_with(env)
         local out = harness.cli({"--format", "json", path},
            env and {env = "TMPDIR=" .. string.format("%q", dir)} or nil)
         local findings = out:match('"id"%s*:%s*"747".-"severity"%s*:%s*"(%a+)"')
         assert_true(findings ~= nil, "luasec reported no 747 at all for " .. path)
         return findings
      end

      assert_equal(severity_with(), "low",
         "with the ambient $TMPDIR this is an ordinary `t/` in an ordinary tree")
      assert_equal(severity_with(true), "high",
         "the same file is scratch space once $TMPDIR says so")

      drop(dir)
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

   it("does not demote a chosen password that happens to be somebody's address", function()
      -- This is the half of the shape with no bound on it, and it is the half
      -- that must not be left as a shape. `admin`, `svc-deploy` and `jenkins`
      -- are three accounts on three real systems, and the next one is nobody's
      -- to enumerate; a rule that demotes `admin@` moves the finding in the
      -- one direction this change may not move.
      --
      -- The assertion is that nothing here is at `low`, rather than that
      -- something here is at `high`: the loop is over what the rule produced,
      -- and a literal that never reaches the rule would pass it by being
      -- absent.
      --
      -- `admin@example.com` is NOT here for that reason. It carries `example`,
      -- and `looks_like_secret` (`src/luasec/rules/secrets.lua`) runs its
      -- `placeholders` table over the lowered value and returns false before
      -- `severity_for` is ever reached - so that literal produces no 747 at
      -- all, before this rule or after it, and asserting over it asserts
      -- nothing. Placeholder literals are covered by the spec that owns
      -- `looks_like_secret`, where a missing finding is the thing asserted;
      -- putting one here is how a spec starts passing for the wrong reason, so
      -- it is left out rather than made to look covered. Every value below
      -- hits no placeholder, does report a 747, and is demoted to `low` or
      -- not at all.
      for _, value in ipairs{ "admin@acme-internal.net",
                              "svc-deploy@staging.acme.com", "jenkins@build.corp.net" } do
         local report = analyze_at("local account_password = " .. string.format("%q", value)
            .. "\nreturn account_password\n", "src/account_login.lua")
         for _, finding in ipairs(with_code(report, "747")) do
            assert_true(finding.severity ~= "low",
               value .. " is a password somebody chose, wearing an address's shape")
         end
      end
   end)

   it("does not demote a password named in a table field either", function()
      -- The corpus shape: a password a deployment put in a configuration
      -- table, in a file that ships. It is still the field, and still the
      -- registered severity.
      local report = analyze_at([[
local account = {
   login = "svc-deploy",
   password = "svc-deploy@staging.acme.com",
}
return account
]], "src/site_config.lua")
      assert_equal(severity_of(report), "high",
         "an address a deployment put in a password field is still a credential")
   end)

   it("still demotes an FTP identity whose local part is the protocol's own name", function()
      -- The half that stays a shape is the DOMAIN - every client picks a
      -- different one - while the local part is the finite set of account
      -- names an anonymous login actually uses. A fix that stopped demoting
      -- `ftp@` altogether would have thrown out the half of the problem that
      -- is real, and this is the spec that notices.
      local report = analyze_at("local PASSWORD = " .. string.format("%q", "ftp@ftp.acme-internal.net")
         .. "\nreturn PASSWORD\n", "src/ftp_client.lua")
      assert_equal(severity_of(report), "low",
         "`ftp@` is an account an anonymous login uses, whatever domain follows it")
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