-- Raw scan: the lexical pass that runs on source text, with or without a parse.
--
-- The module's own entry point is `rawscan.scan_source(source, opts)`: it takes
-- raw text, not a check state, because the whole point is to have an answer for
-- a file the parser threw away. `api.check_source` calls it (see the raw scan
-- call in api.lua); the specs here drive it directly for the unparsed cases
-- because that call site is a separate change with its own owner.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luadoctor.api"
local rawscan = require "luadoctor.rules.rawscan"

local function fixture_source(name)
   local handle = assert(io.open("test/fixtures/rawscan/" .. name, "r"))
   local source = handle:read("*a")
   handle:close()
   return source
end

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

local function with_code(report, code)
   for _, finding in ipairs(report) do
      if finding.code == code then return finding end
   end
   return nil
end

describe("raw scan: a file the parser rejects", function()
   it("reports the execution sink rather than only the parse failure", function()
      local report = rawscan.scan_source(fixture_source("syntax_error_sink.lua"))
      local sink = with_code(report, "701")
      assert_true(sink ~= nil,
         "a command execution with a computed argument is still a command execution; got "
         .. codes(report))
      assert_equal(sink.name, "os.execute")
      assert_equal(sink.line, 5, "the sink is on the fifth line of the fixture")
   end)

   it("reports a sink whose argument is a table constructor", function()
      -- All literals, so nothing in the argument can be the reason this is
      -- dynamic: the table constructor is.
      local report = rawscan.scan_source("os.execute({1, 2, 3})\n")
      assert_equal(codes(report), "701",
         "a table is not a command string, so the call is not a constant; got "
            .. codes(report))
   end)

   it("stays quiet for a sink whose argument is a parenthesised literal", function()
      local report = rawscan.scan_source('os.execute(("id" .. "-un"))\n')
      assert_equal(codes(report), "",
         "literals and the operators between them are a value the scan can read; got "
            .. codes(report))
   end)
end)

describe("raw scan: names that are not code", function()
   it("reports nothing when the only sink names are inside string literals", function()
      local report = rawscan.scan_source(fixture_source("sink_in_string.lua"))
      assert_equal(codes(report), "",
         "a name inside a string is text; the raw scan must not see it as a call")
   end)

   it("reports nothing when the only sink names are inside comments", function()
      local report = rawscan.scan_source(fixture_source("sink_in_comment.lua"))
      assert_equal(codes(report), "",
         "a firmware file documents itself; a comment is not a call")
   end)

   it("reports a backtick command literal in a file the parser cannot read", function()
      local report = rawscan.scan_source(fixture_source("backtick_command.lua"))
      local literal = with_code(report, "711")
      assert_true(literal ~= nil,
         "a shell command between backticks is a command execution; got " .. codes(report))
      assert_equal(literal.line, 4, "the literal is on the fourth line of the fixture")
      assert_match(literal.message, "backtick", "the finding should say what it saw")
   end)
end)

describe("raw scan: constructs the parser cannot read", function()
   it("names the backtick literal as a construct the parser does not support", function()
      local report = rawscan.scan_source(fixture_source("backtick_command.lua"))
      local unsupported = with_code(report, "902")
      assert_true(unsupported ~= nil,
         "a backtick is also why the file will not parse, and the file should say so; got "
            .. codes(report))
      assert_equal(unsupported.name, "backtick command literal",
         "902 has to name the construct, not the file")
   end)

   it("names a 5.4 attribute in a position no Lua version allows", function()
      local report = rawscan.scan_source(fixture_source("attribute_on_global.lua"))
      local unsupported = with_code(report, "902")
      assert_true(unsupported ~= nil,
         "an attribute on a global assignment is why this file will not parse; got "
            .. codes(report))
      assert_equal(unsupported.name, "<const> attribute",
         "902 names the construct so a reader can go look at it")
      assert_equal(unsupported.line, 3, "the attribute is on the third line of the fixture")
   end)
end)

describe("raw scan: dialect mismatch", function()
   it("reports the FFI as unavailable in a file that parses, with no standard configured",
      function()
         local report = api.check_source([[
local ffi = require("ffi")
local C = ffi.C
C.system("id")
]])
         local mismatch = with_code(report, "903")
         assert_true(mismatch ~= nil,
            "the stock library this tool reads has no FFI, so an ffi use is a mismatch; got "
               .. codes(report))
         assert_equal(mismatch.name, "ffi")
         assert_equal(mismatch.line, 1, "the require is on the first line of the source")
      end)

   it("reports no mismatch for the FFI in a parsed file under the LuaJIT profile", function()
      local report = api.check_source([[
local ffi = require("ffi")
local C = ffi.C
C.system("id")
]], {std = "luajit"})
      assert_nil(with_code(report, "903"),
         "LuaJIT has the FFI, so --std luajit is the answer to this finding; got "
            .. codes(report))
   end)

   it("reports the FFI as unavailable when the configured standard is Lua 5.1", function()
      local report = rawscan.scan_source(fixture_source("ffi_escape.lua"), {std = "lua51"})
      local mismatch = with_code(report, "903")
      assert_true(mismatch ~= nil,
         "Lua 5.1 has no FFI, so an ffi use is a dialect mismatch; got " .. codes(report))
      assert_equal(mismatch.name, "ffi",
         "903 has to name the API the standard does not provide")
      assert_equal(mismatch.line, 5,
         "the finding goes on the first mention of ffi in code, which is line 5; the comment "
            .. "on line 2 names ffi.C.system and must not count")
   end)

   it("reports no dialect mismatch for the FFI under the LuaJIT standard", function()
      local report = rawscan.scan_source(fixture_source("ffi_escape.lua"), {std = "luajit"})
      assert_nil(with_code(report, "903"),
         "LuaJIT has the FFI, so under --std luajit there is no mismatch; got " .. codes(report))
   end)

   it("reports the FFI reach into libc as an escape hatch whatever the standard", function()
      local report = rawscan.scan_source(fixture_source("ffi_escape.lua"), {std = "luajit"})
      local escape = with_code(report, "707")
      assert_true(escape ~= nil,
         "ffi.C reaches libc, which is the finding under every standard; got " .. codes(report))
      assert_equal(escape.name, "ffi.C")
      assert_equal(escape.line, 6, "ffi.C is on the sixth line of the fixture")
   end)

   it("reports a 5.4 attribute as unavailable under a 5.1 standard", function()
      local report = rawscan.scan_source(fixture_source("close_attribute.lua"),
         {std = "lua51"})
      local mismatch = with_code(report, "903")
      assert_true(mismatch ~= nil,
         "Lua 5.1 has no <close>, so a 5.1 read of this file is a mismatch; got "
            .. codes(report))
      assert_equal(mismatch.name, "<close> attribute")
      assert_equal(mismatch.line, 4, "the attribute is on the fourth line of the fixture")
      assert_nil(with_code(report, "902"),
         "the parser reads an attribute on a local, so it is a mismatch, not a parse failure")
   end)

   it("reports no mismatch for a 5.4 attribute when no Lua standard is configured", function()
      local report = rawscan.scan_source(fixture_source("close_attribute.lua"))
      assert_equal(codes(report), "",
         "the tool's own baseline is 5.4, so an attribute is what it expects; got "
            .. codes(report))
   end)

   it("reports 5.3 operators as unavailable under the LuaJIT standard", function()
      local report = rawscan.scan_source(fixture_source("bitwise_operator.lua"),
         {std = "luajit"})
      local names = {}
      for _, finding in ipairs(report) do
         if finding.code == "903" then names[#names + 1] = finding.name end
      end
      table.sort(names)
      assert_equal(table.concat(names, ","), "//,<<",
         "LuaJIT is a 5.1 dialect with a bit library and none of the 5.3 operators")
   end)

   it("reports no mismatch for 5.3 operators when no Lua standard is configured", function()
      local report = rawscan.scan_source(fixture_source("bitwise_operator.lua"))
      assert_equal(codes(report), "",
         "the tool's own baseline is 5.4, so a 5.3 operator is what it expects; got "
            .. codes(report))
   end)

   it("follows a local bound to the FFI whatever the local is called", function()
      local report = rawscan.scan_source(fixture_source("ffi_alias.lua"), {std = "lua51"})
      local mismatch = with_code(report, "903")
      assert_true(mismatch ~= nil,
         "require(\"ffi\") is the use, even under another name; got " .. codes(report))
      assert_equal(mismatch.name, "ffi")
      assert_equal(mismatch.line, 4, "the require is on the fourth line of the fixture")
      local escape = with_code(report, "707")
      assert_true(escape ~= nil, "the alias must still reach the escape-hatch table")
      assert_equal(escape.name, "ffi.C",
         "the finding names the capability, not the local a reader cannot search for")
      assert_equal(escape.line, 5, "f.C is on the fifth line of the fixture")
   end)

   it("reports nothing for a table of capability names that is never used", function()
      local report = rawscan.scan_source(fixture_source("module_names_table.lua"),
         {std = "lua51"})
      assert_equal(codes(report), "",
         "naming a module in a table is not reaching for it; got " .. codes(report))
   end)
end)

describe("dialect mismatch through the command line", function()
   it("prints 903 for a LuaJIT capability when no standard is configured", function()
      local out, code = harness.cli({"test/fixtures/rawscan/ffi_escape_parsed.lua"})
      assert_match(out, "903", out)
      assert_match(out, "ffi", "the finding names the API the standard lacks")
      assert_equal(code, 1, "a finding is a non-zero exit")
   end)

   it("prints no 903 for the same file when the LuaJIT profile is configured", function()
      local out = harness.cli({"--std", "luajit",
                               "test/fixtures/rawscan/ffi_escape_parsed.lua"})
      assert_no_match(out, "903", "LuaJIT has the FFI, so there is no mismatch: " .. out)
      assert_match(out, "707", "the escape hatch is still the finding: " .. out)
   end)
end)

describe("raw scan: bytes it could not read", function()
   it("says how much of an unterminated long string it did not read", function()
      local report = rawscan.scan_source(fixture_source("unterminated_long_string.lua"))
      assert_equal(codes(report), "901",
         "the tail is text, not code, so the sinks in it are not findings; got " .. codes(report))
      assert_equal(report[1].name, "unread tail")
      assert_equal(report[1].line, 5, "the long string opens on the fifth line")
      assert_match(report[1].message, "never closed",
         "the message has to say why the file was not read to the end")
      assert_match(report[1].message, "bytes", "and how much was left unread")
   end)

   it("says how much of an unterminated long comment it did not read", function()
      local report = rawscan.scan_source("--[[ os.execute(cmd)\nand more\n")
      assert_equal(codes(report), "901",
         "an unclosed long comment runs to the end of the file; got " .. codes(report))
      assert_match(report[1].message, "never closed")
   end)
end)

describe("raw scan: bounded", function()
   it("reports one finding saying it skipped a file over the size limit", function()
      local report = rawscan.scan_source(string.rep("a", 65), {max_bytes = 64})
      assert_equal(codes(report), "901", "a skipped file gets one finding, not silence")
      assert_equal(report[1].name, "raw scan skipped")
      assert_match(report[1].message, "65 bytes", "the message says how big the file was")
      assert_match(report[1].message, "64 byte", "the message says what the limit is")
   end)

   it("scans a file right up to the size limit", function()
      local report = rawscan.scan_source(string.rep("a", 64), {max_bytes = 64})
      assert_equal(codes(report), "",
         "the limit is inclusive: a file at it is read, not skipped; got " .. codes(report))
   end)

   it("counts the findings past the cap instead of allocating without limit", function()
      local lines = {}
      for index = 1, 30 do
         lines[index] = ("os.execute(command%d)"):format(index)
      end
      local report = rawscan.scan_source(table.concat(lines, "\n"), {max_findings = 5})
      assert_equal(#report, 6, "five detailed findings and one saying how many were not")
      local last = report[#report]
      assert_equal(last.code, "901")
      assert_match(last.message, "25 further", "the count is of what was not detailed")
      assert_match(last.message, "5 finding", "the message names the cap")
   end)
end)

describe("raw scan: hostile input", function()
   -- Every shape below is something a Lua pattern would love to backtrack on:
   -- an unterminated quote or bracket, a long run of one byte, nesting without
   -- an end. The scan applies no pattern to the source and keeps three counters
   -- (bracket depth, token count, path length), so the cost of each is its
   -- length and nothing else.
   local SHAPES = {
      ["one repeated byte"] = string.rep("a", 4096),
      ["an unterminated short string"] = string.rep('"', 4096),
      ["backslashes"] = string.rep("\\", 4096),
      ["an unterminated long string"] = string.rep("[[", 2048),
      ["a long string opened at a level"] = string.rep("[==[", 1024),
      ["an unterminated long comment"] = string.rep("--[[", 1024),
      ["an unterminated backtick"] = string.rep("`", 4096),
      ["a long dotted path"] = string.rep("a.", 2048),
      ["one very long identifier"] = "os." .. string.rep("a", 4090),
      ["nesting with no end"] = string.rep("f(", 2048),
      ["a path that only ever grows"] = string.rep("os.execute(", 512),
      ["newlines"] = string.rep("\n", 4096),
      ["nothing but comment lines"] = string.rep("-- x\n", 200000),
      ["nothing but long comments"] = string.rep("--[[ x ]]\n", 1024),
   }

   for name, source in pairs(SHAPES) do
      it("completes on 4 KB of " .. name, function()
         local started = os.clock()
         local report = rawscan.scan_source(source, {})
         local elapsed = os.clock() - started
         assert_true(elapsed < 2,
            ("4 KB of %s took %.2fs, which is not linear in the input"):format(name, elapsed))
         assert_true(type(report) == "table", "the scan must return, findings or not")
      end)
   end
end)

describe("raw scan: cost in the size of the file", function()
   local UNIT = [[
local function handle(request)
   local target = request.parameter
   os.execute("ping -c1 " .. target)
   return target
end
]]

   local function of_size(bytes)
      return string.rep(UNIT, math.ceil(bytes / #UNIT))
   end

   it("completes on a 5 MB file in time proportional to its size", function()
      local small, large = of_size(640 * 1024), of_size(5 * 1024 * 1024)

      local started = os.clock()
      local small_report = rawscan.scan_source(small, {})
      local small_elapsed = os.clock() - started

      started = os.clock()
      local large_report = rawscan.scan_source(large, {})
      local large_elapsed = os.clock() - started

      assert_true(#large > 5 * 1024 * 1024,
         "the fixture is meant to be over 5 MB, got " .. #large)
      assert_true(#small_report > 0, "the small file is scanned, not skipped")
      assert_true(#large_report > 0, "the large file is scanned, not skipped")

      -- Eight times the bytes. Linear says eight times the work, so the
      -- generous bound here is far under the 64x a quadratic scan would need:
      -- the point is to fail on a superlinear pass, not to measure precisely.
      assert_true(large_elapsed < small_elapsed * 10 + 1.0,
         ("640 KB took %.2fs and 5 MB took %.2fs, which is not proportional"):format(
            small_elapsed, large_elapsed))
      assert_true(large_elapsed < 20,
         ("5 MB took %.2fs"):format(large_elapsed))
   end)
end)

describe("raw scan on a file that does not parse", function()
   it("still reports a command execution sink in an unparseable file", function()
      local report = api.check_source("local x = 1\nthis is not lua ===\nos.execute(\"ping \" .. x)\n")
      local found = {}
      for _, finding in ipairs(report) do found[#found + 1] = finding.code end
      table.sort(found)
      assert_equal(table.concat(found, ","), "701,901",
         "breaking the parser must not be a way to get a clean report")
   end)

   it("does not report a sink that only appears inside a string", function()
      local report = api.check_source("local doc = 'os.execute(\"rm -rf /\")'\nthis is not lua ===\n")
      for _, finding in ipairs(report) do
         assert_true(finding.code ~= "701" and finding.code ~= "702",
            "a sink named inside a string literal is not a sink")
      end
   end)

   it("does not report a sink that only appears inside a comment", function()
      local report = api.check_source("-- os.execute(\"id\")\nthis is not lua ===\n")
      for _, finding in ipairs(report) do
         assert_true(finding.code ~= "701", "a sink named in a comment is not a sink")
      end
   end)
end)

describe("line numbers after a parse error", function()
   it("reports the sink on its own line when earlier lines fail to parse", function()
      local cases = {
         {"x = !\na = 1\nb = 2\nio.popen(c)\n", 4},
         {"if a != 0 then\na = 1\nend\nio.popen(c)\n", 4},
         {"x = !\nlocal s = \"\\-\"\nb = 2\nc = 3\nio.popen(c)\n", 5},
         {"local s = \"\\-\"\na = 1\nb = 2\nc = 3\nx = !\nio.popen(c)\n", 6},
      }
      for _, case in ipairs(cases) do
         local source, expected = case[1], case[2]
         local report = api.check_source(source)
         local sink = with_code(report, "702")
         assert_true(sink ~= nil,
            "expected a 702 finding on line " .. expected .. "; got " .. codes(report))
         assert_equal(sink.line, expected,
            "the 702 finding must be on the io.popen line in " .. string.format("%q", source))
      end
   end)
end)
