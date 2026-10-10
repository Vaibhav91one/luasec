-- Specs for codes 745 (anti-analysis), 746 (embedded machine code), 749
-- (persistence) and 750 (signature pack).
--
-- These four codes were added in one change, so their specs live in one file.
-- Every test uses a public seam only: `luadoctor.api.analyze` on a fixture, or
-- `luadoctor.api.check_source` on a source string built by the test.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true
local assert_nil = harness.assert_nil

local api = require "luadoctor.api"

-- Every finding carrying one code, in report order.
local function with_code(report, code)
   local out = {}
   for _, finding in ipairs(report) do
      if finding.code == code then out[#out + 1] = finding end
   end
   return out
end

-- The codes a report carries, sorted and joined, for failure messages.
local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

local function fixture(path)
   return api.analyze({"test/fixtures/signatures/" .. path .. ".lua"})
end

-- How many keys a set has, for counting ids without depending on order.
local function count_keys(set)
   local count = 0
   for _ in pairs(set) do count = count + 1 end
   return count
end

describe("anti-analysis and watchdog behaviour", function()
   it("reports a debug hook whose mask names call, return and line events as 745", function()
      local report = fixture("anti_analysis/sethook_trap")
      local found = with_code(report, "745")
      assert_equal(#found, 1, "expected one 745, got " .. codes(report))
      assert_equal(found[1].name, "debug.sethook", "the finding names the API it found")
      assert_equal(found[1].severity, "medium")
      assert_equal(found[1].cwe, "CWE-693")
      assert_equal(found[1].hook_mask, "crl", "the finding carries the mask it judged")
      assert_true(found[1].line >= 16, "the finding points at the sethook call, line " ..
         tostring(found[1].line))
   end)

   it("reports nothing for a debug hook that only counts instructions", function()
      local report = fixture("anti_analysis/sethook_count_only")
      assert_equal(#with_code(report, "745"), 0,
         "a count-only hook is instrumentation, not a trap: " .. codes(report))
   end)

   it("reports a while-true loop with an empty body that guards an execution sink as 745", function()
      local report = fixture("anti_analysis/empty_spin")
      local found = with_code(report, "745")
      assert_equal(#found, 1, "expected one 745, got " .. codes(report))
      assert_equal(found[1].name, "infinite loop", "the finding names the shape, not an API")
      assert_equal(found[1].line, 9, "the loop is on line 9 of the fixture")
      assert_equal(found[1].sink, "os.execute", "the finding names the sink the loop guards")
   end)

   it("reports nothing for a stack walk that returns and a counted loop", function()
      local report = fixture("anti_analysis/bounded_spin")
      assert_equal(#with_code(report, "745"), 0,
         "a loop that can leave is not a watchdog: " .. codes(report))
   end)

   it("reports each execution sink whose failure a discarded pcall throws away as 745", function()
      local report = fixture("anti_analysis/suppressed_exec")
      local found = with_code(report, "745")
      assert_equal(#found, 2, "expected two 745s, got " .. codes(report))
      assert_equal(found[1].name, "pcall(os.execute)", "the finding names the wrapped API")
      assert_equal(found[1].sink, "os.execute")
      assert_equal(found[1].line, 7, "the first discarded pcall is on line 7")
      assert_equal(found[2].name, "pcall(io.popen)")
   end)

   it("reports nothing for a pcall that keeps its result or wraps a safe call", function()
      local report = fixture("anti_analysis/pcall_result_used")
      assert_equal(#with_code(report, "745"), 0,
         "an error that is handled is not a hidden trace: " .. codes(report))
   end)

   it("reports the os.exit that ends a function which has just loaded code as 745", function()
      local report = fixture("anti_analysis/exit_after_load")
      local found = with_code(report, "745")
      assert_equal(#found, 1, "expected one 745, got " .. codes(report))
      assert_equal(found[1].name, "os.exit")
      assert_equal(found[1].line, 15, "the exit that ends the function is on line 15")
   end)

   it("reports nothing for an exit that is a failure path or an ordinary shutdown", function()
      local report = fixture("anti_analysis/exit_benign")
      assert_equal(#with_code(report, "745"), 0,
         "quitting on a missing file or at the end of a request is not a trap: " .. codes(report))
   end)

   it("reports the shapes inside every kind of loop body, stepped loops included", function()
      -- A `for` with a step keeps its body one slot further along than a `for`
      -- without one, so a walk that only knows the second spelling reads the
      -- step as the body and finds nothing inside it.
      local report = api.check_source([[
local function stepped()
   for attempt = 1, 9, 2 do
      pcall(os.execute("probe " .. attempt))
   end
   for plain = 1, 9 do
      pcall(os.execute("probe " .. plain))
   end
   for name in pairs({}) do
      pcall(os.execute("probe " .. name))
   end
   while true do
      local info = debug.getinfo(2, "Sl")
      if not info then break end
   end
   repeat
      pcall(os.execute("probe again"))
   until true
end

local function do_unused()
   for attempt = 1, 9, 2 do
      while true do end
   end
end

return {stepped, do_unused}
]])
      local found = with_code(report, "745")
      assert_equal(#found, 5, "four discarded pcalls and one empty spin loop, expected 5, "
         .. "got " .. codes(report))
      local spins, pcalls = 0, 0
      for _, finding in ipairs(found) do
         if finding.name == "infinite loop" then
            spins = spins + 1
         elseif finding.name == "pcall(os.execute)" then
            pcalls = pcalls + 1
         end
      end
      assert_equal(spins, 1, "the empty spin loop inside the stepped for is found")
      assert_equal(pcalls, 4, "one discarded pcall per loop body, stepped or not")
   end)
end)

describe("embedded machine code", function()
   it("reports a long run of 0x90 bytes spelled out with string.char as 746", function()
      local report = fixture("shellcode/nop_sled")
      local found = with_code(report, "746")
      assert_equal(#found, 1, "expected one 746, got " .. codes(report))
      assert_equal(found[1].name, "nop sled", "the finding names the shape it matched")
      assert_equal(found[1].severity, "critical")
      assert_equal(found[1].cwe, "CWE-506")
      assert_equal(found[1].length, 16, "the finding says how many bytes the run is")
   end)

   it("reports an ELF and a PE header as 746, each named for the format", function()
      local report = fixture("shellcode/executable_headers")
      local found = with_code(report, "746")
      assert_equal(#found, 2, "expected two 746s, got " .. codes(report))
      assert_equal(found[1].name, "ELF header")
      assert_equal(found[2].name, "PE header")
      for _, finding in ipairs(found) do
         assert_equal(finding.confidence, "high", "a header is a shape, not a guess")
         assert_equal(finding.byte_source, "string literal",
            "the finding says where the bytes came from")
      end
   end)

   it("reports a connect-back stub as 746 shellcode and a run of prologues as 746 prologue", function()
      local report = fixture("shellcode/connect_back_stub")
      local found = with_code(report, "746")
      assert_equal(#found, 2, "expected two 746s, got " .. codes(report))
      assert_equal(found[1].name, "shellcode")
      assert_equal(found[1].confidence, "medium",
         "the shellcode class is the statistical one, so it is reported as a guess")
      assert_equal(found[1].byte_source, "string.char")
      assert_equal(found[2].name, "x86-64 prologue")
   end)

   it("reports nothing for base64, hex, a source snippet, a four-byte magic and four NOPs", function()
      local report = fixture("shellcode/looks_binary")
      assert_equal(#with_code(report, "746"), 0,
         "text is not machine code however much it looks like it: " .. codes(report))
   end)
end)

describe("blob scanning stays linear", function()
   -- A detector that reads bytes with a Lua pattern spends the reader's CPU in
   -- proportion to how hard the input pushes back. These are the two inputs
   -- that do it: one character repeated, and an alternation with nothing to
   -- anchor it. Both are handed to check_source as real source, so the whole
   -- pipeline is timed, not just the shape test.
   local function hostile_source(bytes)
      local run = string.rep("\144", bytes)
      local alternation = ("\\144\\144\\144\\144\\144\\145\\145\\145\\145\\145"):rep(bytes / 50)
      return "local run = \"" .. run .. "\"\n"
         .. "local alt = \"" .. alternation .. "\"\n"
         .. "return run, alt\n"
   end

   local function elapsed(source)
      local started = os.clock()
      local report = api.check_source(source)
      return os.clock() - started, report
   end

   it("finishes a 20000 byte run of one byte and a 20000 byte alternation", function()
      local seconds, report = elapsed(hostile_source(20000))
      assert_equal(#with_code(report, "901"), 0, "no rule raised on the hostile file")
      assert_true(#with_code(report, "746") >= 1,
         "the NOP run is still found: it is a linear scan that finds it, got " .. codes(report))
      assert_true(seconds < 5, "took " .. string.format("%.2f", seconds) ..
         "s, which is not a scan, it is a backtrack")
   end)

   it("costs about four times as much for four times the bytes", function()
      local small, _ = elapsed(hostile_source(2500))
      local large, _ = elapsed(hostile_source(10000))
      -- A linear scan scales by the input; a backtracking matcher does not
      -- reach four at all. The floor keeps the ratio meaningful when the small
      -- run finishes inside the clock's resolution.
      local allowed = math.max(small * 8, 0.5)
      assert_true(large < allowed, string.format(
         "2500 bytes took %.3fs and 10000 took %.3fs, over the %.3fs a linear scan allows",
         small, large, allowed))
   end)
end)

describe("persistence installed by the script", function()
   it("reports a line appended to /etc/rc.local as 749, naming the path", function()
      local report = fixture("persistence/rc_local")
      local found = with_code(report, "749")
      assert_equal(#found, 1, "expected one 749, got " .. codes(report))
      assert_equal(found[1].path, "/etc/rc.local", "the finding names the file it would boot from")
      assert_equal(found[1].name, "boot file append")
      assert_equal(found[1].severity, "high")
      assert_equal(found[1].cwe, "CWE-506")
      assert_equal(found[1].line, 9, "the append is on line 9 of the fixture")
      assert_nil(found[1].staged,
         "nothing in that file fetches or chmods anything, so the finding says nothing about it")
      assert_nil(found[1].downloaded, "and it does not claim a download it cannot see")
   end)

   it("reports a service written under /etc/init.d and calls out the staging around it", function()
      local report = fixture("persistence/init_d_service")
      local found = with_code(report, "749")
      assert_equal(#found, 1, "expected one 749, got " .. codes(report))
      assert_equal(found[1].path, "/etc/init.d/stage2")
      assert_equal(found[1].name, "boot file write")
      assert_equal(found[1].staged, "download, chmod",
         "the finding says the file was fetched and made runnable")
   end)

   it("reports a crontab table piped in as 749", function()
      local report = fixture("persistence/crontab_install")
      local found = with_code(report, "749")
      assert_equal(#found, 1, "expected one 749, got " .. codes(report))
      assert_equal(found[1].name, "crontab install")
      assert_equal(found[1].path, "crontab")
   end)

   it("reports a uci firewall rule that opens a port as 749", function()
      local report = fixture("persistence/uci_firewall")
      local found = with_code(report, "749")
      assert_equal(#found, 1, "expected one 749, got " .. codes(report))
      assert_equal(found[1].name, "uci firewall rule")
      assert_equal(found[1].line, 8, "the rule that opens the port is on line 8")
   end)

   it("reports a systemd unit written and enabled as two 749s, one per mechanism", function()
      local report = fixture("persistence/systemd_unit")
      local found = with_code(report, "749")
      assert_equal(#found, 2, "expected two 749s, got " .. codes(report))
      assert_equal(found[1].name, "boot file write")
      assert_equal(found[1].path, "/etc/systemd/system/stage2.service")
      assert_equal(found[2].name, "systemctl enable")
      assert_equal(found[2].path, "stage2.service")
   end)

   it("reports nothing for a write to /tmp, a read of a boot file or crontab -l", function()
      local report = fixture("persistence/tmp_and_crontab_read")
      assert_equal(#with_code(report, "749"), 0,
         "none of these survives a reboot: " .. codes(report))
   end)
end)

describe("the signature pack", function()
   local PACK_PATH = "src/luadoctor/registry/stds/signatures.lua"
   local YARA_PATH = "yara/lua_doctor_signatures.yar"

   -- The pack as the analyzer loads it. A data file is loaded by running it,
   -- which is the same thing the analyzer does with `require`, and the same
   -- thing an operator does with `--rules`, so the load goes through the public
   -- seam an operator uses rather than through an internal.
   local function load_pack()
      local ok, declaration = pcall(function()
         local chunk, err = loadfile(PACK_PATH)
         assert(chunk, tostring(err))
         return chunk()
      end)
      assert_true(ok, "the pack must load: " .. tostring(declaration))
      return declaration
   end

   it("reports a known Mirai signature in a string literal as 750 with the signature and the pack version", function()
      local report = fixture("pack_mirai")
      local found = with_code(report, "750")
      assert_equal(#found, 3, "expected one 750 per signature matched, got " .. codes(report))
      assert_equal(found[1].severity, "critical")
      assert_equal(found[1].cwe, "CWE-1203")
      assert_equal(found[1].signature, "mirai-default-credentials",
         "the finding names the signature that matched")
      assert_true(found[1].pack_version ~= nil and found[1].pack_version ~= "",
         "the finding says which version of the pack matched")
      assert_equal(found[1].line, 7, "the credential table is on line 7 of the fixture")
      local ids = {}
      for _, finding in ipairs(found) do ids[#ids + 1] = finding.signature end
      table.sort(ids)
      assert_equal(table.concat(ids, ","),
         "mirai-default-credentials,mirai-loader-paths,mirai-user-agent")
   end)

   it("reports the same pack version on every 750 it produces", function()
      local report = fixture("pack_mirai")
      local version
      for _, finding in ipairs(with_code(report, "750")) do
         version = version or finding.pack_version
         assert_equal(finding.pack_version, version, "one pack, one version in one report")
      end
      assert_equal(version, load_pack().version, "and it is the version the pack declares")
   end)

   it("reports a known signature found in the file's text but in no string literal", function()
      local report = fixture("pack_signature_in_text")
      local found = with_code(report, "750")
      assert_equal(#found, 1, "expected one 750, got " .. codes(report))
      assert_equal(found[1].signature, "mirai-default-credentials")
      assert_equal(found[1].line, 7, "the match is in the comment on line 7")
   end)

   it("reports nothing for an ordinary device script", function()
      local report = fixture("pack_clean")
      assert_equal(#with_code(report, "750"), 0,
         "a base64 blob, a user-agent and a password are not signatures: " .. codes(report))
   end)

   it("loads through the public rules seam an operator uses", function()
      local ok = api.validate_options({rules = {PACK_PATH}})
      assert_true(ok, "lua-doctor must accept the pack file as a data file it can load")
   end)

   it("carries a version, and one id, description and pattern per signature", function()
      local pack = load_pack()
      assert_true(type(pack.version) == "string" and pack.version ~= "",
         "the pack declares the version a finding reports")
      assert_true(#pack.signatures >= 5, "a pack of " .. #pack.signatures .. " signatures")
      local ids = {}
      for _, signature in ipairs(pack.signatures) do
         assert_true(type(signature.id) == "string" and signature.id ~= "",
            "every signature has an id")
         assert_true(type(signature.description) == "string" and signature.description ~= "",
            signature.id .. " has a description")
         assert_true(type(signature.pattern) == "string" and signature.pattern ~= "",
            signature.id .. " has a pattern")
         assert_true(not ids[signature.id], "id " .. signature.id .. " is unique")
         ids[signature.id] = true
         for alternative in (signature.pattern .. "|"):gmatch("([^|]*)|") do
            assert_true(alternative ~= "", signature.id .. " has no empty alternative")
            assert_true(#alternative >= 4,
               signature.id .. " alternative " .. string.format("%q", alternative) ..
               " is too short to be a signature on its own")
            assert_true(alternative:find("[\"\\]") == nil,
               signature.id .. " alternative " .. string.format("%q", alternative) ..
               " cannot be written verbatim in a yara rule")
         end
      end
   end)

   it("lists the same signatures, with the same alternatives, as the yara ruleset", function()
      local handle = assert(io.open(YARA_PATH, "r"))
      local rules = handle:read("*a")
      handle:close()

      -- Each rule names its signature in `id` and then lists its alternatives,
      -- so an alternative belongs to the id that was read before it.
      local yara_ids, yara_alternatives, current = {}, {}, nil
      for line in (rules .. "\n"):gmatch("([^\n]*)\n") do
         local id = line:match('^%s*id%s*=%s*"([^"]*)"')
         if id then
            yara_ids[id] = true
            current = id
         end
         local _, text = line:match('^%s*%$([%w]+)%s*=%s*"([^"]*)"')
         if text and current then
            yara_alternatives[#yara_alternatives + 1] = current .. "\1" .. text
         end
      end

      local pack_ids, pack_alternatives = {}, {}
      for _, signature in ipairs(load_pack().signatures) do
         pack_ids[signature.id] = true
         for alternative in (signature.pattern .. "|"):gmatch("([^|]*)|") do
            pack_alternatives[#pack_alternatives + 1] = signature.id .. "\1" .. alternative
         end
      end

      table.sort(yara_alternatives)
      table.sort(pack_alternatives)
      assert_equal(table.concat(yara_alternatives, ","), table.concat(pack_alternatives, ","),
         "the yara ruleset and the Lua pack must match the same text; " ..
         "yara/lua_doctor_signatures.yar has drifted from " .. PACK_PATH)
      assert_equal(count_keys(yara_ids), count_keys(pack_ids),
         "the yara ruleset and the Lua pack must hold the same number of signatures")
      for id in pairs(pack_ids) do
         assert_true(yara_ids[id], "signature " .. id .. " is in the pack and not in the yara ruleset")
      end
   end)

   it("compiles with yara when yara is installed on this machine", function()
      local pipe = io.popen("command -v yara 2>/dev/null")
      local installed = pipe and pipe:read("*l") or nil
      if pipe then pipe:close() end
      if not installed then return end

      local run = io.popen(("%s -w %s test/fixtures/signatures/pack_mirai.lua 2>&1")
         :format(installed, YARA_PATH))
      local out = run and run:read("*a") or ""
      if run then run:close() end
      assert_true(out:find("mirai_default_credentials", 1, true) ~= nil,
         "yara must compile the ruleset and match the fixture it is given: " .. out)
   end)
end)

describe("a large generated file", function()
   -- Ten lines per block: a debug hook that traps, a NOP sled spelled out byte
   -- by byte, a crontab table piped in, and three lines that are none of those
   -- things. 1000 blocks is 10000 lines, which is the size at which a walk that
   -- is accidentally quadratic starts costing seconds instead of milliseconds.
   local function generate(blocks)
      local parts = {}
      for index = 1, blocks do
         parts[#parts + 1] = string.format([[
local function watch_%d()
   local function on_call()
      return debug.getinfo(2, "Sl")
   end
   debug.sethook(on_call, "cr", 512)
   return "%d"
end

local sled_%d = string.char(%s)
local install_%d = function()
   os.execute("echo '%d * * * * /tmp/job' | crontab -")
end
]], index, index, index, string.rep("144, ", 15) .. "144", index, index, index)
      end
      -- One return for the whole chunk: `return` has to be its last statement.
      parts[#parts + 1] = "\nreturn {watch_1, sled_1, install_1}\n"
      return table.concat(parts, "\n")
   end

   it("finds every hook, sled and crontab in 10000 generated lines", function()
      local source = generate(1000)
      local total_lines = select(2, source:gsub("\n", "")) + 1
      assert_true(total_lines > 10000, "the generated file is over 10000 lines, got " .. total_lines)

      local started = os.clock()
      local report = api.check_source(source)
      local seconds = os.clock() - started

      assert_equal(#with_code(report, "901"), 0, "no rule raised on the generated file")
      assert_equal(#with_code(report, "745"), 1000, "one hook per generated block")
      assert_equal(#with_code(report, "746"), 1000, "one NOP sled per generated block")
      assert_equal(#with_code(report, "749"), 1000, "one crontab install per generated block")
      assert_true(seconds < 30, "10000 lines took " .. string.format("%.1f", seconds) ..
         "s, which is not a scan of a linear shape")
   end)
end)
