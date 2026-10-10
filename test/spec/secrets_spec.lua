local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, assert_match

local api = require "luadoctor.api"

-- The codes a report carries, sorted and joined, for exact-match assertions.
local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

-- Every finding carrying one code, in report order.
local function with_code(report, code)
   local out = {}
   for _, finding in ipairs(report) do
      if finding.code == code then out[#out + 1] = finding end
   end
   return out
end

local function fixture(name)
   return api.analyze({"test/fixtures/secrets/" .. name .. ".lua"})
end

-- The secret must not survive anywhere in the finding, in any form.
local function assert_no_secret(finding, secret)
   for key, value in pairs(finding) do
      if type(value) == "string" then
         assert_true(value:find(secret, 1, true) == nil,
            "the finding's " .. key .. " quotes the secret: " .. value)
      end
   end
end

describe("hardcoded credentials", function()
   it("reports a password literal bound to a credential-named local as 747, without quoting the value", function()
      -- The fixture is under test/fixtures/, so the file it lives in is a test
      -- file and 747 lowers the finding to `low` (#290). Everything this test is
      -- about - that the literal is found at all, that the name is the binding
      -- and not the value, that the length and the masked form are what the
      -- report carries - is unchanged by that, and the severity of a credential
      -- in code that ships is what test/spec/secrets_scope_spec.lua covers.
      local report = fixture("hardcoded_password")
      local found = with_code(report, "747")
      assert_equal(#found, 1, "expected one 747, got " .. codes(report))
      assert_equal(found[1].name, "telnet_password", "the finding names the binding, not the value")
      assert_equal(found[1].severity, "low",
         "the fixture is a file in a test tree, which is not shipped (#290)")
      assert_equal(found[1].kind, "password")
      assert_equal(found[1].length, 11, "the length is reported instead of the value")
      assert_no_secret(found[1], "s3cr3t-pass")
      assert_true(found[1].redacted:find("%*") ~= nil, "the masked form hides the middle: " .. found[1].redacted)
   end)

   it("reports a PEM private key literal as 747, showing only its header", function()
      local report = fixture("private_key")
      local found = with_code(report, "747")
      assert_equal(#found, 1, "expected one 747, got " .. codes(report))
      assert_equal(found[1].kind, "pem")
      assert_true(found[1].length > 100, "the whole block is measured: " .. found[1].length)
      assert_equal(found[1].redacted, "-----BEGIN RSA PRIVATE KEY----- (194 bytes)",
         "the header is not secret, the body is not shown at all")
      assert_true(found[1].redacted:find("MIIEow", 1, true) == nil, "no key material is quoted")
   end)

   it("reports a private key block filed under a name that says nothing", function()
      local report = fixture("inline_pem")
      local found = with_code(report, "747")
      assert_equal(#found, 1, "expected one 747, got " .. codes(report))
      assert_equal(found[1].kind, "pem", "the block says what it is, whatever the name says")
      assert_equal(found[1].redacted, "-----BEGIN EC PRIVATE KEY----- (185 bytes)",
         "the header is reported, the body is not")
      assert_true(found[1].redacted:find("MHcCAQEE", 1, true) == nil, "no key material is quoted")
   end)
end)

describe("the marker of a PEM", function()
   it("reports no 747 for the table of BEGIN/END lines a script wraps a key in", function()
      local report = fixture("pem_header_table")
      assert_equal(#with_code(report, "747"), 0,
         "a `-----BEGIN ...-----` line is a marker, not the key it introduces: " .. codes(report))
   end)

   it("reports the base64 body a marker introduces, and not the marker", function()
      local report = fixture("pem_marker_and_body")
      local found = with_code(report, "747")
      assert_equal(#found, 1,
         "the marker is not a secret and the body is: " .. codes(report))
      assert_equal(found[1].name, "key_body", "the finding lands on the body, not on the marker")
      assert_equal(found[1].line, 10, "the body is the long-bracket literal on line 10")
      assert_equal(found[1].kind, "key")
      assert_true(found[1].length > 300, "the whole body is measured: " .. found[1].length)
      assert_true(found[1].redacted:find("MIIEvQ", 1, true) == nil,
         "no key material is quoted: " .. found[1].redacted)
      assert_true(#found[1].redacted <= 20,
         "a long value does not redact to a long run of nothing: " .. #found[1].redacted)
      assert_true(found[1].length > 300, "the length carries the size instead: " .. found[1].length)
   end)
end)

describe("a constant that is not embedded in the program", function()
   it("reports no 747 for a login form that compares a password or a token constant", function()
      local report = fixture("login_check")
      assert_equal(#with_code(report, "747"), 0,
         "a value compared once is the check, not a secret shipped with the program: " .. codes(report))
   end)

   it("reports no 747 for a table of default credentials a program validates against", function()
      local report = fixture("default_credentials")
      assert_equal(#with_code(report, "747"), 0,
         "a credential dictionary the program tests input against is the validator: " .. codes(report))
   end)

   it("reports no 747 for the paths a firmware script hands its TLS library", function()
      local report = fixture("ca_certificate_path")
      assert_equal(#with_code(report, "747"), 0,
         "naming the file a key lives in is not carrying the key: " .. codes(report))
   end)

   it("reports no 747 for a credential fielded by name and read from a file", function()
      local report = fixture("config_password_field")
      assert_equal(#with_code(report, "747"), 0,
         "the value comes from the file, and the default is empty: " .. codes(report))
   end)
end)

describe("credential-named values that are not secrets", function()
   it("reports no 747 for a prompt, a placeholder, a mode, an empty string or a path", function()
      local report = fixture("placeholders")
      assert_equal(#with_code(report, "747"), 0,
         "a name that says secret and a value that says nothing was embedded: " .. codes(report))
   end)

   it("reports no 747 for a qualifying name holding a path, a URL, a format string, an enum, a number or a protocol word", function()
      local report = fixture("not_a_secret_value")
      assert_equal(#with_code(report, "747"), 0,
         "the name says secret and the value says none of it was embedded: " .. codes(report))
   end)

   it("reports no 747 for a bare `key` or `auth` holding a protocol or mode name", function()
      local report = fixture("protocol_names")
      assert_equal(#with_code(report, "747"), 0,
         "a name that says secret and a value that is a protocol name: " .. codes(report))
   end)

   it("reports no 747 for a table of limits keyed by the name of the limit", function()
      local report = fixture("limit_table")
      assert_equal(#with_code(report, "747"), 0,
         "a bare `key` holding a field name is a table index, not a key: " .. codes(report))
   end)
end)

describe("keys written into a program", function()
   it("reports a pre-shared key and two API keys held in configuration tables as 747 kind key", function()
      local report = fixture("psk_table")
      local found = with_code(report, "747")
      assert_equal(#found, 3, "expected three 747, got " .. codes(report))
      assert_equal(found[1].name, "psk")
      assert_equal(found[1].kind, "key", "a psk is a key, not a password")
      assert_equal(found[1].redacted, "hu******00",
         "the first two and last two characters, the middle starred")
      assert_equal(found[2].name, "apikey")
      assert_equal(found[2].kind, "key")
      assert_equal(found[3].name, "key", "a bare `key` with digits in it is a key")
      assert_equal(found[3].confidence, "low",
         "a bare `key` is weak evidence, and the confidence has to say so")
      assert_equal(found[1].confidence, "high",
         "a `psk` is a credential in its own right, so the name is the evidence")
      assert_equal(found[2].confidence, "high", "an `apikey` is a credential in its own right")
      assert_no_secret(found[1], "hunter2000")
      assert_no_secret(found[2], "9f2c41ab77de3058")
      assert_no_secret(found[3], "b41d8ef2a97c")
   end)

   it("reports a literal handed to a parameter the program itself names for a secret", function()
      local report = fixture("credential_argument")
      local found = with_code(report, "747")
      assert_equal(#found, 1, "expected one 747, got " .. codes(report))
      assert_equal(found[1].name, "password", "the finding names the parameter, not the value")
      assert_equal(found[1].line, 10, "the call is on line 10 of the fixture")
      assert_no_secret(found[1], "toor")
   end)
end)

describe("secrets that really are embedded", function()
   -- The corpus this rule is measured on has no hardcoded credential in it, so
   -- without these four a clean corpus would only prove the rule is quiet.
   it("reports the admin password a router script ships", function()
      local report = fixture("router_default_password")
      local found = with_code(report, "747")
      assert_equal(#found, 1,
         "a shipped admin password is the finding this rule exists for: " .. codes(report))
      assert_equal(found[1].name, "ADMIN_PASSWORD", "the name is the binding, verbatim")
      assert_equal(found[1].kind, "password")
      assert_equal(found[1].length, 5, "five characters is a real credential length here")
      assert_equal(found[1].confidence, "high", "the name is the evidence")
      assert_no_secret(found[1], "admin")
   end)

   it("reports the PSK a WiFi config generator ships", function()
      local report = fixture("wifi_psk_generator")
      local found = with_code(report, "747")
      assert_equal(#found, 1,
         "the pre-shared key in the image is the key the installer writes: " .. codes(report))
      assert_equal(found[1].name, "guest_psk")
      assert_equal(found[1].kind, "key", "a psk is a key, not a password")
      assert_no_secret(found[1], "correcthorsebattery9")
   end)

   it("reports an API token whose name is in capitals", function()
      local report = fixture("api_token")
      local found = with_code(report, "747")
      assert_equal(#found, 1,
         "case is not part of a name, so API_TOKEN is a credential name: " .. codes(report))
      assert_equal(found[1].name, "API_TOKEN")
      assert_equal(found[1].kind, "token")
      assert_no_secret(found[1], "ghp_4eC39Jqklj3nR2vB8sY1wZ5")
   end)

   it("reports a complete private key block, quoting none of the body", function()
      local report = fixture("embedded_private_key")
      local found = with_code(report, "747")
      assert_equal(#found, 1,
         "one block, one finding: " .. codes(report))
      assert_equal(found[1].kind, "pem")
      assert_true(found[1].length > 400, "the whole block is measured: " .. found[1].length)
      assert_match(found[1].redacted, "^%-%-%-%-%-BEGIN RSA PRIVATE KEY%-%-%-%-%- ",
         "the header is the only part of a PEM a report may carry: " .. found[1].redacted)
      assert_true(found[1].redacted:find("Lh%pclU9", 1, true) == nil, "no key material is quoted")
   end)
end)

describe("what a report is allowed to show", function()
   it("keeps the secret out of every report format the CLI can print", function()
      for _, format in ipairs{"plain", "json", "sarif", "html"} do
         local out = harness.cli({"--format", format, "test/fixtures/secrets/hardcoded_password.lua"})
         assert_true(out:find("s3cr3t-pass", 1, true) == nil,
            "the " .. format .. " report quotes the secret:\n" .. out)
         assert_match(out, "747", "the " .. format .. " report still reports the finding")
      end
   end)
end)

describe("scanner and brute-force loops", function()
   it("reports a loop that connects, reads a banner and sends a credential as 748", function()
      local report = fixture("brute_force")
      local found = with_code(report, "748")
      assert_equal(#found, 1, "expected one 748, got " .. codes(report))
      assert_equal(found[1].name, "send", "the finding names the sink the credential went to")
      assert_equal(found[1].severity, "critical")
      assert_equal(found[1].line, 9, "the loop is on line 9 of the fixture")
      assert_equal(found[1].read, "receive", "the banner read is part of the shape")
      assert_equal(found[1].connect, "connect")
   end)

   it("reports no 748 for a client loop that connects and sends an ordinary request", function()
      local report = fixture("http_client")
      assert_equal(#with_code(report, "748"), 0,
         "connecting in a loop is not a scanner; nothing credential-shaped is sent: " .. codes(report))
   end)

   it("reports a loop that walks a table of credential lines and sends each one as 748", function()
      local report = fixture("credential_pairs")
      local found = with_code(report, "748")
      assert_equal(#found, 1, "expected one 748, got " .. codes(report))
      assert_equal(found[1].name, "send", "the line is sent without a credential name in the expression")
      assert_equal(found[1].line, 9, "the loop is on line 9 of the fixture")
   end)

   it("reports a loop that calls a helper which connects and sends the credential as 748", function()
      local report = fixture("helper_scanner")
      local found = with_code(report, "748")
      assert_equal(#found, 1, "expected one 748, got " .. codes(report))
      assert_equal(found[1].line, 15, "the loop is on line 15 of the fixture")
      assert_equal(found[1].name, "send", "the sink is the helper's send, which is where the credential went")
   end)
end)

describe("hostile secret shapes", function()
   it("reads long names, long values and a PEM-like prefix without crashing", function()
      local report = fixture("hostile_shapes")
      assert_equal(#with_code(report, "901"), 0,
         "a rule that cannot handle a shape stays silent rather than raising: " .. codes(report))
      assert_equal(#with_code(report, "748"), 1, "one scanner loop in the file: " .. codes(report))
      assert_equal(#with_code(report, "747"), 1, "one embedded key in the file: " .. codes(report))
   end)
end)

describe("a large generated file", function()
   -- Ten lines per block: a credential in a table, a socket loop that sends it,
   -- and a value that is none of those things. 1000 blocks is 10000 lines.
   local function generate(blocks)
      local parts = {}
      for index = 1, blocks do
         parts[#parts + 1] = table.concat({
            "do",
            string.format("   local creds = {password = 'p%06d', user = 'admin'}", index),
            "   for _, entry in ipairs(creds) do",
            "      local client = socket.tcp()",
            "      if client:connect('10.0.0.1', 23) then",
            "         local banner = client:receive('*l')",
            "         client:send(entry.password .. '\\n')",
            "         client:close()",
            "      end",
            "   end",
            "end",
            "",
         }, "\n")
      end
      return table.concat(parts, "\n")
   end

   it("finds every credential and every scanner loop in 10000 generated lines", function()
      local source = generate(1000)
      local total_lines = select(2, source:gsub("\n", "")) + 1
      assert_true(total_lines > 10000, "the generated file is over 10000 lines, got " .. total_lines)

      local report = api.check_source(source)
      assert_equal(#with_code(report, "901"), 0, "no rule raised on the generated file")
      assert_equal(#with_code(report, "747"), 1000, "one 747 per generated block")
      assert_equal(#with_code(report, "748"), 1000, "one 748 per generated block")
   end)
end)

describe("a secret the code never binds to a name", function()
   it("reports a uci.set key argument, and the value that follows it", function()
      local report = fixture("uci_key")
      local found = with_code(report, "747")
      assert_equal(#found, 2, "expected two 747, got " .. codes(report))
      assert_equal(found[1].name, "key", "the config key names the finding")
      assert_equal(found[2].name, "password", "a method call is read the same way")
   end)

   it("reports a CBI field assigned through .default and .value", function()
      local report = fixture("cbi_default")
      local found = with_code(report, "747")
      assert_equal(#found, 3, "expected three 747, got " .. codes(report))
      assert_equal(found[1].name, "Password", "the builder's label names the finding")
   end)

   it("reports a secret concatenated from constants at author time", function()
      local report = fixture("concatenated")
      local found = with_code(report, "747")
      assert_equal(#found, 2, "expected two 747, got " .. codes(report))
      -- The value never appears: it is the concatenation, not the literal.
      assert_no_secret(found[1], "AAAA1234")
   end)
end)

describe("747 on firmware that has no credential in it", function()
   it("stays silent for a CBI field's own descriptors", function()
      -- datatype, optional, rmempty, password and depends all take short
      -- strings, and a CBI field is usually NAMED after the secret. Reporting
      -- the validator expression is a false positive on real firmware.
      local report = fixture("cbi_descriptor")
      assert_equal(codes(report), "",
         "a CBI descriptor is not a credential: " .. codes(report))
   end)

   it("stays silent for a set or add method on something that is not a cursor", function()
      -- A suffix match on `set` fired on encoders, key/value stores and plain
      -- helper tables. Only the profile-declared writers and uci cursors count.
      local report = fixture("not_a_config_write")
      assert_equal(codes(report), "",
         "an ordinary set method is not a config write: " .. codes(report))
   end)
end)

describe("747 on a config write the analysis has to recognise", function()
   it("reads every spelling of a uci cursor firmware uses", function()
      -- The module is aliased to muci in most of the corpus, the cursor often
      -- hangs off a table, and sometimes a helper returns one. Matching the
      -- literal spelling `uci.cursor` found the one shape that is not used.
      local report = fixture("cursor_writes")
      local found = with_code(report, "747")
      assert_equal(#found, 5, "five config writes, so five 747: " .. codes(report))
   end)

   it("does not read another library's cursor as a config write", function()
      local report = fixture("not_a_uci_cursor")
      assert_equal(codes(report), "",
         "store.cursor() and a set method are not a config write: " .. codes(report))
   end)
end)

describe("747 in a file with a multiple assignment", function()
   it("still runs, and still finds the secret", function()
      -- A `Set` with more targets than values gives a nil on the right-hand
      -- side. Reading a field of it raised inside the rule, and the rule
      -- carries 741 through 749, so a two-line idiom cost the file every
      -- secrets finding in it. Four files in the corpus trip it.
      local api = require "luadoctor.api"
      local handle = assert(io.open("test/fixtures/multiple_assignment.lua", "r"))
      local report = api.check_source(handle:read("*a"),
         {std = "+openwrt+luci+luajit"})
      handle:close()

      local failed = false
      for _, finding in ipairs(report) do
         if finding.code == "901" and (finding.message or ""):find("rule failed") then
            failed = true
         end
      end
      assert_true(not failed, "a multiple assignment is not a rule failure: " ..
         codes(report))
      assert_equal(codes(report), "701",
         "the file is analyzed in full, so the sink is found")
   end)
end)

describe("a field that holds a cursor on one path", function()
   it("is read as a cursor", function()
      local report = fixture("branch_cursor")
      assert_equal(codes(report), "747",
         "the credential in the set is reported: " .. codes(report))
   end)
end)

describe("747 on a cursor stored rather than called", function()
   it("reads a handle that is bound, aliased, or read off self", function()
      -- The summary that makes this rule linear asked whether the assigned value
      -- was a CALL rather than whether it was a cursor, and those are different
      -- questions. Six shapes went dark and six others became false positives
      -- from that one substitution; a hardcoded root password written through a
      -- stored cursor was not reported, which is the direction this may not fail
      -- in. Nothing caught it: the corpus measures 747 = 0 either way.
      local report = fixture("stored_cursor")
      local found = with_code(report, "747")
      assert_equal(#found, 2,
         "two config writes through a stored cursor: " .. codes(report))
      assert_equal(found[1].name, "root_password", "the config key names the finding")
   end)

   it("does not read a field named uci as a cursor when it holds something else", function()
      local report = fixture("not_a_cursor_factory")
      assert_equal(codes(report), "",
         "a method table, a plain factory and a metatable are not config handles: "
            .. codes(report))
   end)
end)

describe("747 on a file built to be expensive to analyse", function()
   it("does not take unbounded time on a field-assignment lattice", function()
      -- The answer is computed in a pre-pass that runs once per field
      -- assignment, and the walk behind it is one branch per reaching
      -- definition per hop. Unbounded in depth and in fan-out, a 369-line file
      -- did not finish in 300 seconds and an ordinary 40,000-line module took
      -- 28 where it had taken 1.2. --max-nodes does not help: `var.values` is
      -- filled by the parser and exists even when resolve_locals was skipped.
      --
      -- The bound is the point of this test, so the threshold is loose: it is
      -- here to catch a hang and an order-of-magnitude regression, not to
      -- measure.
      local lines = {"local t = {}", "local x"}
      for index = 1, 40 do lines[#lines + 1] = "x = " .. index end
      for alias = 2, 5 do
         lines[#lines + 1] = "local y" .. alias .. "; y" .. alias .. " = x"
         for _ = 1, 40 do
            lines[#lines + 1] = "y" .. alias .. " = y" .. (alias + 1)
         end
      end
      lines[#lines + 1] = 't.uci = y5'
      lines[#lines + 1] = 't.uci:set("system", "root_password", "R00tPassw0rd-2024")'

      local started = os.clock()
      local ok = pcall(api.check_source, table.concat(lines, "\n"),
         {std = "+openwrt+luci"})
      local elapsed = os.clock() - started

      assert_true(ok, "the lattice is analysed without raising")
      assert_true(elapsed < 10,
         "a 200-line lattice took " .. elapsed .. " s; the walk is unbounded")
   end)
end)
