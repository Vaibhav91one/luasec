local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luasec.api"

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
   return api.analyze({"test/fixtures/payload/" .. name .. ".lua"})
end

describe("obfuscated code loaders", function()
   it("reports a base64-decoded blob reaching loadstring as 741, with the decode chain in its trace", function()
      local report = fixture("base64_loader")
      local found = with_code(report, "741")
      assert_equal(#found, 1, "expected one 741, got " .. codes(report))
      assert_equal(found[1].name, "loadstring", "the finding names the loader API")
      assert_equal(found[1].severity, "critical")
      assert_equal(found[1].line, 6, "the loadstring call is on line 6 of the fixture")
      assert_true(#found[1].trace >= 2, "the trace names the decoder and the loader")
      assert_equal(found[1].trace[1].name, "base64decode", "the first trace step is the decoder")
      assert_equal(found[1].trace[#found[1].trace].name, "loadstring", "the last trace step is the loader")
   end)

   it("reports a local function that rebuilds a string byte by byte feeding loadstring as 741", function()
      local report = fixture("char_decoder")
      local found = with_code(report, "741")
      assert_equal(#found, 1, "expected one 741, got " .. codes(report))
      assert_equal(found[1].name, "loadstring")
      assert_equal(found[1].confidence, "medium", "a decoded chain is more than shape")
      local names = {}
      for _, step in ipairs(found[1].trace) do names[#names + 1] = step.name end
      assert_equal(table.concat(names, " -> "), "decode -> byte building -> loadstring",
         "the trace names the decoder, what it does, and the loader")
   end)

   it("reports a table of byte codes turned into a string and loaded as 741", function()
      local report = fixture("byte_table")
      local found = with_code(report, "741")
      assert_equal(#found, 1, "expected one 741, got " .. codes(report))
      assert_equal(found[1].name, "loadstring")
      local names = {}
      for _, step in ipairs(found[1].trace) do names[#names + 1] = step.name end
      assert_equal(table.concat(names, " -> "), "byte building -> loadstring")
   end)

   it("names the helper and what it does when a byte table is assembled at runtime and loaded", function()
      local report = fixture("byte_table_helper")
      local found = with_code(report, "741")
      assert_equal(#found, 1, "expected one 741, got " .. codes(report))
      local names = {}
      for _, step in ipairs(found[1].trace) do names[#names + 1] = step.name end
      assert_equal(table.concat(names, " -> "), "assemble -> byte building -> loadstring")
   end)

   it("names the byte table when the helper that joins it shows no decoder of its own", function()
      local report = fixture("byte_table_join")
      local found = with_code(report, "741")
      assert_equal(#found, 1, "expected one 741, got " .. codes(report))
      local names = {}
      for _, step in ipairs(found[1].trace) do names[#names + 1] = step.name end
      assert_equal(table.concat(names, " -> "), "byte table -> loadstring")
   end)

   it("follows a decoded payload parked in a module field back to its decoder", function()
      local report = fixture("module_field")
      local found = with_code(report, "741")
      assert_equal(#found, 1, "expected one 741, got " .. codes(report))
      assert_equal(found[1].line, 14, "the loadstring is on line 14 of the fixture")
      local names = {}
      for _, step in ipairs(found[1].trace) do names[#names + 1] = step.name end
      assert_equal(table.concat(names, " -> "), "unpack_bytes -> byte building -> loadstring",
         "the field write is followed, not taken at face value")
   end)

   it("follows a decoded payload held in a table constructor and read back by key", function()
      local report = fixture("config_table")
      local found = with_code(report, "741")
      assert_equal(#found, 1, "expected one 741, got " .. codes(report))
      assert_equal(found[1].line, 15, "the loadstring is on line 15 of the fixture")
      local names = {}
      for _, step in ipairs(found[1].trace) do names[#names + 1] = step.name end
      assert_equal(table.concat(names, " -> "), "decode -> byte building -> loadstring")
   end)

   it("follows a decoder reached as a method call", function()
      local report = fixture("method_decoder")
      local found = with_code(report, "741")
      assert_equal(#found, 1, "expected one 741, got " .. codes(report))
      assert_equal(found[1].line, 19, "the loadstring is on line 19 of the fixture")
      local names = {}
      for _, step in ipairs(found[1].trace) do names[#names + 1] = step.name end
      assert_equal(table.concat(names, " -> "), "decode -> loadstring",
         "the method name is read from the call, so a decoder behind a colon is still a decoder")
   end)
end)

-- A `load` or `loadstring` the file defines itself is a different function with a
-- different meaning, so what its body does decides the reading. Stock upstream
-- LuCI ships one: cbi.lua defines `load` as its own module loader over `loadfile`
-- and every call to it in that file is module loading, not a payload.
describe("a loader name the file shadows", function()
   it("reports no 741 when the shadowing load resolves to loadfile and so is a module loader", function()
      local report = fixture("module_loader")
      assert_equal(#with_code(report, "741"), 0,
         "a load that compiles a module off disk is module loading, not a hidden payload: "
            .. codes(report))
      assert_true(#with_code(report, "703") >= 1,
         "the name is still a dynamic-evaluation sink, so it is still reported: " .. codes(report))
   end)

   -- The negative. Silencing every shadowed `load` would delete the rule instead
   -- of correcting it: this one decodes a blob and its definition hands that blob
   -- to the standard `loadstring`, which is the backdoor shape exactly.
   it("still reports 741 critical when a shadowing load is handed a decoded blob and loads it", function()
      local report = fixture("shadowed_backdoor")
      local found = with_code(report, "741")
      assert_equal(#found, 1, "a shadowed name must not switch the rule off: " .. codes(report))
      assert_equal(found[1].name, "load", "the finding names the call as the file wrote it")
      assert_equal(found[1].severity, "critical",
         "the definition reaches loadstring itself, so the evaluation is not a guess")
      local names = {}
      for _, step in ipairs(found[1].trace) do names[#names + 1] = step.name end
      assert_equal(table.concat(names, " -> "), "base64decode -> load",
         "the trace names the decoder and the loader")
   end)

   it("reports a decoded blob handed to the standard, unshadowed load as 741 critical", function()
      local report = api.check_source([[
local encoded = "b2NobyBoaQ=="
local payload = base64decode(encoded)
local chunk = load(payload, "=stage")
]])
      local found = with_code(report, "741")
      assert_equal(#found, 1, "expected one 741, got " .. codes(report))
      assert_equal(found[1].severity, "critical",
         "the standard load is the interpreter's, so a decoded chunk reaching it is the worst case")
   end)

   it("reports a shadowing load whose body shows no evaluation as high rather than critical", function()
      local report = fixture("shadowed_unknown")
      local found = with_code(report, "741")
      assert_equal(#found, 1, "the name and the decode chain still say something: " .. codes(report))
      assert_equal(found[1].severity, "high",
         "the definition never reaches a loader, so only the name says it evaluates code")
      assert_equal(found[1].confidence, "low",
         "the chain is a heuristic about a shadowed name, so it is not reported as more than shape")
   end)
end)

describe("loaders fed values the program never decoded", function()
   it("reports neither 741 nor 743 for a loader given a parameter, a concatenation, a plain field or a request", function()
      local report = fixture("undecoded_loader")
      assert_equal(#with_code(report, "741"), 0,
         "a visible value handed to a loader is a 703 shape, not an obfuscation: " .. codes(report))
      assert_equal(#with_code(report, "743"), 0, "no decode chain, so no 743: " .. codes(report))
   end)
end)

describe("decoded data reaching an execution sink", function()
   it("reports a hex-decoded blob handed to os.execute as 743 critical, naming the sink", function()
      local report = fixture("decoded_exec")
      local found = with_code(report, "743")
      assert_equal(#found, 1, "expected one 743, got " .. codes(report))
      assert_equal(found[1].name, "os.execute")
      assert_equal(found[1].severity, "critical")
      assert_equal(found[1].line, 13, "the os.execute call is on line 13 of the fixture")
      local names = {}
      for _, step in ipairs(found[1].trace) do names[#names + 1] = step.name end
      assert_equal(table.concat(names, " -> "), "unpack_bytes -> byte building -> os.execute")
   end)

   it("reports no 743 for a command sink given a parameter, a field, a request or a literal", function()
      local report = fixture("undecoded_exec")
      assert_equal(#with_code(report, "743"), 0,
         "an argument the program never decoded is a 701, not a decoded payload: " .. codes(report))
   end)

   it("reports a decoded value concatenated into a command as 743", function()
      local report = fixture("decoded_concat")
      local found = with_code(report, "743")
      assert_equal(#found, 1, "expected one 743, got " .. codes(report))
      local names = {}
      for _, step in ipairs(found[1].trace) do names[#names + 1] = step.name end
      assert_equal(table.concat(names, " -> "), "from_hex -> substitution decode -> os.execute",
         "a substitution decoder is named in the chain too")
   end)

   it("raises both 741 and 743 for a decoded chunk handed to dofile, which is a loader and a sink", function()
      local report = fixture("dofile_decoded")
      assert_equal(#with_code(report, "741"), 1, "dofile is a code loader too: " .. codes(report))
      assert_equal(#with_code(report, "743"), 1, "dofile is an execution sink: " .. codes(report))
   end)
end)

describe("hostile payload shapes", function()
   it("reads a long identifier, a value rebound thousands of times and a deep concatenation without crashing", function()
      local report = fixture("hostile_shapes")
      assert_equal(#with_code(report, "901"), 0,
         "a rule that cannot handle a shape stays silent rather than raising: " .. codes(report))
      assert_equal(#with_code(report, "743"), 0, "nothing decoded reached a sink: " .. codes(report))
      -- Only the table assembled at run time and handed to the loader is a chain.
      assert_equal(#with_code(report, "741"), 1, "expected one 741, got " .. codes(report))
      assert_equal(with_code(report, "741")[1].confidence, "low",
         "a call this file does not define is shape only")
   end)
end)

describe("a large generated file", function()
   -- Five lines per block: a byte table, an os.execute that decodes it, and the
   -- two ends. 2000 blocks is 10000 lines, and the payload sits on the last one
   -- so a detector that gave up early would not find it.
   local function generate(blocks)
      local parts = {}
      for index = 1, blocks do
         parts[#parts + 1] = table.concat({
            "do",
            string.format("   local bytes%d = {%d, %d, %d}", index, index, index + 1, index + 2),
            string.format("   os.execute(string.char(unpack(bytes%d)))", index),
            "end",
            "",
         }, "\n")
      end
      parts[#parts + 1] = table.concat({
         "local function run()",
         "   return loadstring(base64decode('b2NobyBoaQ=='))()",
         "end",
         "return run",
      }, "\n")
      return table.concat(parts, "\n")
   end

   it("finds every decoded payload and the loader on the last line of 10000 generated lines", function()
      local source = generate(2000)
      local total_lines = select(2, source:gsub("\n", "")) + 1
      assert_true(total_lines > 10000, "the generated file is over 10000 lines, got " .. total_lines)

      local report = api.check_source(source)
      assert_equal(#with_code(report, "901"), 0, "no rule raised on the generated file")
      assert_equal(#with_code(report, "743"), 2000, "one 743 per generated block")
      local loaders_found = with_code(report, "741")
      assert_equal(#loaders_found, 1, "the loader on the final line is the only 741")

      local where = assert(source:find("loadstring", 1, true), "the generated file has a loader")
      local expected_line = select(2, source:sub(1, where - 1):gsub("\n", "")) + 1
      assert_equal(loaders_found[1].line, expected_line,
         "the finding sits on the loader at the end of the file")
      assert_true(expected_line > total_lines - 5, "the loader is in the last few lines, at " .. expected_line)
   end)
end)
