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
       assert_match(err, "luasec: Scanned %d+ files in %d+s\n$", err)
      assert_true(not out:find("analyzing", 1, true), "stdout carries no progress")
   end)

   it("does not change the report", function()
      local plain = run({DIR})
      local shown = run({"--progress", DIR})
      assert_equal(shown, plain, "stdout is the same with progress on")
   end)

   it("names the walk and report phases around the counter", function()
      local _, err = run({"--progress", DIR})
      local finding = err:find("luasec: finding Lua files", 1, true)
      local first = err:find("luasec: analyzing", 1, true)
      local building = err:find("luasec: building the report", 1, true)
      local last = nil
      local from = 1
      while true do
         local at = err:find("luasec: analyzing", from, true)
         if not at then break end
         last = at
         from = at + 1
      end
      assert_true(finding and first and finding < first,
         "finding Lua files comes before the first analyzing line: " .. err)
      assert_true(building and last and building > last,
         "building the report comes after the last analyzing line: " .. err)
   end)

   it("shows neither phase without progress, and stdout is identical", function()
      local out_on, _ = run({"--progress", DIR})
      local out_off, err_off = run({"--no-progress", DIR})
      assert_true(not err_off:find("finding Lua files", 1, true), "no phase: " .. err_off)
      assert_true(not err_off:find("building the report", 1, true), "no phase: " .. err_off)
      assert_equal(out_on, out_off, "stdout is byte-identical with and without progress")
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
   it("draws a phase and a file counter on a live terminal without error", function()
      local progress = require "luasec.cli.progress"
      local reporter = progress.new({progress = true})
      reporter.live = true
      local real = io.stderr
      local sink = io.open(harness.scratch_dir("progress_live") .. "/err", "w")
      io.stderr = sink
      local ok, failure = pcall(function()
         reporter:phase("finding Lua files")
         reporter:file(1, 2, "a/b.lua")
         reporter:finish(2)
      end)
      io.stderr = real
      sink:close()
      assert_true(ok, tostring(failure))
   end)
end)
