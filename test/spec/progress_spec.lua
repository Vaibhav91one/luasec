local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_true

local DIR = "test/fixtures/firmware"

-- Stdout and stderr captured apart: harness.cli merges them, which is the one
-- thing this spec must not do.
local function run(args)
   local scratch = harness.scratch_dir("progress")
   local cmd = "./bin/luasec"
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

describe("progress", function()
   it("prints nothing to stderr by default when stderr is not a terminal", function()
      local _, err = run({DIR})
      assert_equal(err, "", "no terminal, no progress")
   end)

   it("shows the phases and a counter as plain lines with --progress", function()
      local out, err = run({"--progress", DIR})
      assert_match(err, "luasec: listing files under test/fixtures/firmware\n", err)
      assert_match(err, "luasec: found %d+ files to analyze\n", err)
      assert_match(err, "luasec: analyzing %d+/%d+ files %(100%%%)\n", err)
      assert_match(err, "luasec: analyzed %d+ files in %d+s\n$", err)
      assert_true(not out:find("analyzing", 1, true), "stdout carries no progress")
   end)

   it("does not change the report", function()
      local plain = run({DIR})
      local shown = run({"--progress", DIR})
      assert_equal(shown, plain, "stdout is the same with progress on")
   end)

   it("is turned off by --no-progress and by --quiet, even with --progress", function()
      local _, off = run({"--progress", "--no-progress", DIR})
      assert_equal(off, "", "--no-progress wins")
      local _, quiet = run({"--progress", "--quiet", DIR})
      assert_equal(quiet, "", "--quiet wins")
   end)

   it("says when it is resolving calls across files", function()
      local _, err = run({"--progress", "--whole-program", DIR})
      assert_match(err, "luasec: resolving calls across files\n", err)
   end)
end)
