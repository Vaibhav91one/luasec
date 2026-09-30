local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_true

local api = require "luasec.api"

local function scan(name, bytes)
   local dir = harness.scratch_dir("binary_input")
   local path = dir .. "/" .. name
   local handle = assert(io.open(path, "wb"))
   handle:write(bytes)
   handle:close()
   local report = api.analyze({path})
   os.execute("rm -rf " .. string.format("%q", dir))
   return report
end

local BACKTICKS = "`id`\n`reboot`\n"

describe("a binary file given as input", function()
   it("is one coverage finding that says what it looks like, not Lua findings", function()
      local report = scan("fw.bin", "hsqs" .. string.rep("\0", 64) .. BACKTICKS)
      assert_equal(#report, 1, "one finding, not a lexical scan of the bytes")
      assert_equal(report[1].code, "901", "a coverage finding")
      assert_match(report[1].message, "a squashfs image", report[1].message)
      assert_match(report[1].message, "extract it", report[1].message)
   end)

   it("names a tar archive, a UBI image and plain binary data", function()
      local tar = scan("a.tar", string.rep("\0", 257) .. "ustar" .. string.rep("\0", 100) .. BACKTICKS)
      assert_match(tar[1].message, "a tar archive", tar[1].message)
      local ubi = scan("a.ubi", "UBI#" .. string.rep("\0", 64))
      assert_match(ubi[1].message, "a UBI image", ubi[1].message)
      local blob = scan("a.img", "\122\29\1\0" .. string.rep("\0", 64) .. BACKTICKS)
      assert_match(blob[1].message, "binary data", blob[1].message)
   end)

   it("does not treat ordinary source as binary, including bytes above 127", function()
      local report = scan("ok.lua", "local s = 'caf\195\169'\nreturn s\n")
      assert_equal(#report, 0, "clean source stays clean")
   end)

   it("still reports a real finding in a text file", function()
      local report = api.analyze({"test/fixtures/tainted_exec/handler.lua"})
      assert_equal(report[1].code, "709", "text is still analyzed")
   end)

   it("fails the run through the CLI with the same message", function()
      local dir = harness.scratch_dir("binary_cli")
      local handle = assert(io.open(dir .. "/fw.bin", "wb"))
      handle:write("hsqs" .. string.rep("\0", 64) .. BACKTICKS)
      handle:close()
      local out, code = harness.cli({dir .. "/fw.bin"})
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 1, out)
      assert_match(out, "%[901%]", out)
      assert_true(not out:find("[711]", 1, true), "no backtick findings: " .. out)
   end)
end)
