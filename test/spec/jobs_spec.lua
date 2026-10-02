-- `--jobs N`: a per-file scan split over N worker processes. The report is the
-- contract, so the subject here is that a parallel run writes the same bytes as
-- a serial one, in every format, including for a file that cannot be parsed.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_no_match =
   harness.assert_equal, harness.assert_match, harness.assert_no_match

local function write_file(path, text)
   local handle = assert(io.open(path, "w"))
   handle:write(text)
   handle:close()
end

-- Six files, so four workers each get a slice: three with a finding, two
-- clean, and one that does not parse (a 901 has to survive the trip too).
local function tree()
   local dir = harness.scratch_dir("jobs")
   for index = 1, 3 do
      write_file(("%s/rce%d.lua"):format(dir, index), table.concat({
         "local function ping(host)",
         '   os.execute("ping -c1 " .. http.formvalue(host))',
         "end",
         "return ping",
      }, "\n") .. "\n")
   end
   write_file(dir .. "/clean1.lua", "return 1\n")
   write_file(dir .. "/clean2.lua", "local t = {}\nreturn t\n")
   write_file(dir .. "/broken.lua", "local x = = 1\n")
   return dir
end

local function stdout_of(args)
   local cmd = "./bin/luasec"
   for _, a in ipairs(args) do cmd = cmd .. " " .. string.format("%q", a) end
   local pipe = assert(io.popen(cmd .. " 2>/dev/null"))
   local out = pipe:read("*a")
   pipe:close()
   return out
end

describe("--jobs", function()
   it("writes the same report with one worker and with four, in every format", function()
      local dir = tree()
      for _, format in ipairs({"json", "sarif", "plain", "html"}) do
         local serial = stdout_of({"--no-progress", "--std", "+luci", "--jobs", "1", "--format", format, dir})
         local parallel = stdout_of({"--no-progress", "--std", "+luci", "--jobs", "4", "--format", format, dir})
         assert_match(serial, "rce3%.lua", format .. " report names every file:\n" .. serial)
         assert_match(serial, "broken%.lua", format .. " report keeps the 901:\n" .. serial)
         assert_equal(parallel, serial, format .. " differs between --jobs 1 and --jobs 4")
      end
      os.execute(("rm -rf %q"):format(dir))
   end)

   it("says it is analyzing in worker processes", function()
      local dir = tree()
      local out = harness.cli({"--progress", "--jobs", "4", dir})
      os.execute(("rm -rf %q"):format(dir))
      assert_match(out, "analyzing in 4 worker processes", out)
   end)

   it("stays in one process for --whole-program, which needs every file at once", function()
      local dir = tree()
      local out = harness.cli({"--progress", "--whole-program", "--jobs", "4", dir})
      os.execute(("rm -rf %q"):format(dir))
      assert_no_match(out, "worker processes", out)
   end)
end)
