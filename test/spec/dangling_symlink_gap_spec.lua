local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match, assert_no_match =
   harness.assert_equal, harness.assert_true, harness.assert_match, harness.assert_no_match

local function q(text) return string.format("%q", text) end

-- An extracted image with one Lua file in it, so the run is a real scan and not
-- an empty tree that happens to be clean.
local function tree(tag)
   local dir = harness.scratch_dir(tag)
   os.execute("mkdir -p " .. q(dir .. "/etc") .. " " .. q(dir .. "/usr/sbin") .. " " .. q(dir .. "/bin"))
   local handle = assert(io.open(dir .. "/ok.lua", "w"))
   handle:write("local x = 1\nreturn x\n")
   handle:close()
   return dir
end

describe("a dangling symlink into runtime state of the machine the image would be mounted on", function()
   it("is not a coverage gap on an extracted image", function()
      -- The three links every OpenWrt-family image has shipped for fifteen
      -- years. They name runtime state of a MOUNTED system; on an extraction
      -- they resolve to nothing on any machine, and none of them can be Lua.
      local dir = tree("runtime_links")
      os.execute("ln -s /proc/self/mounts " .. q(dir .. "/etc/mtab"))
      os.execute("ln -s /tmp/localtime " .. q(dir .. "/etc/localtime"))
      os.execute("ln -s /tmp/TZ " .. q(dir .. "/etc/TZ"))
      local out, code = harness.cli({dir})
      os.execute("rm -rf " .. q(dir))
      assert_true(not out:find("[901]", 1, true),
         "a complete scan must not report a coverage gap for runtime links: " .. out)
      assert_equal(code, 0, out)
   end)
end)

describe("a dangling symlink to a place inside the image that is simply not there", function()
   it("still reports a coverage gap", function()
      -- The other half of the decision. A target inside the image names a
      -- location the extraction really could have carried, so a Lua file that
      -- is not there is a Lua file this scan could not reach, and silence here
      -- would trade a cosmetic false positive for the tool failing to say it
      -- missed something.
      local dir = tree("inside_image")
      os.execute("mkdir -p " .. q(dir .. "/usr/lib/lua") .. " " .. q(dir .. "/usr/sbin") .. " " .. q(dir .. "/bin"))
      os.execute("ln -s /usr/lib/lua/absent.lua " .. q(dir .. "/bin/handler.lua"))
      local out, code = harness.cli({dir})
      os.execute("rm -rf " .. q(dir))
      assert_match(out, "could not resolve symlink", out)
      assert_match(out, "bin/handler.lua", out)
      assert_match(out, "coverage gap", out)
      assert_equal(code, 1, out)
   end)

   it("still reports when the target climbs out of a runtime directory and back into the image", function()
      -- `/tmp/../usr/lib/absent.lua` is a place the image could have carried and
      -- does not, whatever runtime root it starts by spelling. Reading only the
      -- leading `/tmp/` would exempt it and lose the gap.
      local dir = tree("inside_image_dotdot")
      os.execute("mkdir -p " .. q(dir .. "/usr/lib") .. " " .. q(dir .. "/bin"))
      os.execute("ln -s /tmp/../usr/lib/absent.lua " .. q(dir .. "/usr/lib/handler.lua"))
      os.execute("ln -s /proc/../usr/lib/other.lua " .. q(dir .. "/usr/lib/second.lua"))
      local out, code = harness.cli({dir})
      os.execute("rm -rf " .. q(dir))
      assert_match(out, "could not resolve symlink", out)
      assert_match(out, "coverage gap", out)
      assert_equal(code, 1, out)
   end)
end)

describe("the score of a scan whose only unresolvable links point at runtime state", function()
   it("is a complete score, not an incomplete one", function()
      -- The second half of the complaint: a run that analysed everything was
      -- scored `incomplete`, which is a downstream decision made on false
      -- information about the one signal that says the scan was not whole.
      local dir = tree("runtime_score")
      os.execute("ln -s /proc/self/mounts " .. q(dir .. "/etc/mtab"))
      os.execute("ln -s /sys/class/net " .. q(dir .. "/etc/netclass"))
      os.execute("ln -s /dev/console " .. q(dir .. "/etc/console"))
      os.execute("ln -s /tmp/localtime " .. q(dir .. "/etc/localtime"))
      local out, code = harness.cli({dir})
      os.execute("rm -rf " .. q(dir))
      assert_match(out, "Score:", out)
      assert_no_match(out, "incomplete", out)
      assert_no_match(out, "coverage gap", out)
      assert_equal(code, 0, out)
   end)
end)

describe("a directory inside the image that merely starts with a runtime root's name", function()
   it("is a place inside the image, so a missing file there still reports", function()
      -- Where the line is drawn. `/tmpfiles` and `/processes` are ordinary
      -- directories a firmware ships; only the directory ITSELF being runtime
      -- state exempts a link. Matching on the leading letters instead of the
      -- directory would silence these too, and silently lose real gaps.
      local dir = tree("runtime_lookalikes")
      os.execute("ln -s /tmpfiles/absent.lua " .. q(dir .. "/bin/a.lua"))
      os.execute("ln -s /processes/absent.lua " .. q(dir .. "/bin/b.lua"))
      os.execute("ln -s /devtools/absent.lua " .. q(dir .. "/bin/c.lua"))
      os.execute("ln -s /syslog/absent.lua " .. q(dir .. "/bin/d.lua"))
      local out, code = harness.cli({dir})
      os.execute("rm -rf " .. q(dir))
      assert_match(out, "could not resolve symlink", out)
      assert_match(out, "coverage gap", out)
      assert_equal(code, 1, out)
   end)
end)

describe("a dangling link into an ordinary directory under /tmp", function()
   it("still reports, because /tmp is writable storage and not a runtime pseudo-filesystem", function()
      -- /proc, /sys and /dev have their CONTENTS synthesised by the kernel at
      -- boot. /tmp does not: it is an ordinary writable directory, and anything
      -- a firmware or an operator put there is content, not machine state.
      -- The path is fixed rather than under TMPDIR so this holds whether the
      -- harness runs where TMPDIR points into /tmp (Linux CI) or elsewhere.
      local dir = tree("tmp_ordinary")
      os.execute("ln -s /tmp/luasec-absent-dir/handler.lua " .. q(dir .. "/bin/linked.lua"))
      local out, code = harness.cli({dir})
      os.execute("rm -rf " .. q(dir))
      assert_match(out, "could not resolve symlink", out)
      assert_match(out, "coverage gap", out)
      assert_equal(code, 1, out)
   end)
end)