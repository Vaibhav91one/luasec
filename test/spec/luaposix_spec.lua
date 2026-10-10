-- luaposix's process-execution calls, declared from the library's own source (v36.3,
-- tag e6b94b37c19c4bd19a7dc475a4f4cb56f61f5da9), not from the shape of the call:
--   ext/posix/unistd.c:289-356   runexec: exec = execv, execp = execvp, (path, argt-TABLE); no shell form
--   lib/posix/deprecated.lua:295-350,653,663   posix.exec/execp(path, ...) : argv is a table OR the
--        remaining string arguments, so `exec("/bin/sh", "-c", cmd)` has the command at argument 3
--   lib/posix/init.lua:117-123,215-225,236-244,337,375,384,397   execx/spawn(task, ...), popen(task, mode),
--        popen_pipeline(tasks, mode):
--        argument 1 is a function or a table {program, arg, ...} handed to execp
-- (#297, the luaposix half of #278). `posix.exec.*` was declared before and matched nothing.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal = harness.assert_equal

local api = require "luadoctor.api"

local function exec_findings(source)
   local out = {}
   for _, finding in ipairs(api.check_source(source, {std = "openwrt"})) do
      if finding.code == "709" then out[#out + 1] = finding end
   end
   return out
end

local function expect_sink(source, sink)
   local found = exec_findings(source)
   assert_equal(#found, 1, "one command-execution finding expected for " .. sink .. ", got " .. #found)
   assert_equal(found[1].sink, sink)
end

describe("luaposix command execution (#297)", function()
   it("reports a request parameter used as the program of posix.exec and posix.execp", function()
      expect_sink('local posix = require "posix"\nposix.exec(http.formvalue("p"))\n', "posix.exec")
      expect_sink('local posix = require "posix"\nposix.execp(http.formvalue("p"))\n', "posix.execp")
   end)

   it("reports the command of the exec('/bin/sh', '-c', cmd) idiom at argument 3", function()
      expect_sink('local posix = require "posix"\nposix.exec("/bin/sh", "-c", http.formvalue("c"))\n', "posix.exec")
   end)

   it("reports a request parameter inside the argv table of posix.unistd.exec / execp", function()
      expect_sink('local unistd = require "posix.unistd"\nunistd.exec("/bin/sh", {"-c", http.formvalue("c")})\n',
         "posix.unistd.exec")
      expect_sink('local posix = require "posix"\nposix.unistd.execp(http.formvalue("p"), {})\n',
         "posix.unistd.execp")
   end)

   it("reports a request parameter in a task given to posix.spawn, execx and popen", function()
      expect_sink('local posix = require "posix"\nposix.spawn({"/bin/sh", "-c", http.formvalue("t")})\n', "posix.spawn")
      expect_sink('local posix = require "posix"\nposix.execx({http.formvalue("t")})\n', "posix.execx")
      expect_sink('local posix = require "posix"\nposix.popen({"/bin/sh", "-c", http.formvalue("t")}, "r")\n', "posix.popen")
   end)

   it("reports the sh -c command of posix.execp at argument 3 and of posix.popen_pipeline's tasks", function()
      expect_sink('local posix = require "posix"\nposix.execp("/bin/sh", "-c", http.formvalue("c"))\n', "posix.execp")
      expect_sink('local posix = require "posix"\nposix.popen_pipeline({{"/bin/sh", "-c", http.formvalue("t")}}, "r")\n',
         "posix.popen_pipeline")
   end)

   it("stays quiet when every argument is a constant", function()
      assert_equal(#exec_findings('local posix = require "posix"\nposix.exec("/bin/ls", "-l")\n'), 0)
      assert_equal(#exec_findings('local posix = require "posix"\nposix.spawn({"/bin/ls", "-l"})\n'), 0)
   end)

   it("no longer declares the nonexistent posix.exec.* namespace", function()
      local handle = assert(io.open("src/luadoctor/registry/stds/openwrt.lua", "r"))
      local text = handle:read("*a")
      handle:close()
      assert_equal(text:find('pattern = "posix.exec.*"', 1, true), nil,
         "posix.exec is a function in luaposix, not a namespace; this pattern matches nothing")
   end)
end)
