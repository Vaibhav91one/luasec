local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_true

local DIR = "test/fixtures/firmware"

-- Stdout and stderr apart, with an optional environment prefix.
local function run(args, env)
   local scratch = harness.scratch_dir("term")
   local cmd = (env or "") .. " ./bin/luasec"
   for _, a in ipairs(args) do cmd = cmd .. " " .. string.format("%q", a) end
   os.execute(("%s >%q 2>%q </dev/null"):format(cmd, scratch .. "/out", scratch .. "/err"))
   local function read(name)
      local handle = assert(io.open(scratch .. "/" .. name, "rb"))
      local text = handle:read("*a")
      handle:close()
      return text
   end
   local out, err = read("out"), read("err")
   os.execute("rm -rf " .. string.format("%q", scratch))
   return out, err
end

describe("colour", function()
   it("is off when the output is not a terminal", function()
      local out, err = run({"--progress", DIR})
      assert_true(not out:find("\27", 1, true), "no escape codes on stdout")
      assert_true(not err:find("\27", 1, true), "no escape codes on stderr")
   end)

   it("is forced on by --color, and shows in the progress lines", function()
      local out, err = run({"--progress", "--color", DIR})
      assert_match(err, "\27%[", err)
      assert_match(err, "analyzing", err)
      assert_true(not out:find("\27", 1, true), "the report on stdout stays plain unless it is a terminal")
   end)

   it("is off with --no-color and with NO_COLOR, even with --color", function()
      local _, off = run({"--progress", "--color", "--no-color", DIR})
      assert_true(not off:find("\27", 1, true), "--no-color wins over --color")
      local _, env = run({"--progress", DIR}, "NO_COLOR=1")
      assert_true(not env:find("\27", 1, true), "NO_COLOR is honoured")
   end)
end)
