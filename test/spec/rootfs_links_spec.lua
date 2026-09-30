local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_true

local function q(text) return string.format("%q", text) end

local function tree(tag)
   local dir = harness.scratch_dir(tag)
   os.execute("mkdir -p " .. q(dir .. "/usr/sbin") .. " " .. q(dir .. "/bin"))
   local handle = assert(io.open(dir .. "/ok.lua", "w"))
   handle:write("local x = 1\nreturn x\n")
   handle:close()
   return dir
end

local function count(text, pattern)
   local n = 0
   for _ in text:gmatch(pattern) do n = n + 1 end
   return n
end

describe("absolute symlinks in an extracted rootfs", function()
   it("are not gaps when the target exists under the scanned root", function()
      local dir = tree("rootfs_inside")
      local handle = assert(io.open(dir .. "/usr/sbin/daemon", "w"))
      handle:write("not lua\n")
      handle:close()
      os.execute("ln -s /usr/sbin/daemon " .. q(dir .. "/bin/daemon"))
      os.execute("ln -s //usr/sbin " .. q(dir .. "/sbin"))
      local out, code = harness.cli({dir})
      os.execute("rm -rf " .. q(dir))
      assert_equal(code, 0, out)
      assert_true(not out:find("[901]", 1, true), "no coverage warning for links that resolve inside: " .. out)
   end)

   it("become one finding with a count when they do not resolve", function()
      local dir = tree("rootfs_dangling")
      for i = 1, 5 do
         os.execute(("ln -s /usr/sbin/missing%d %s"):format(i, q(dir .. "/bin/missing" .. i)))
      end
      local out, code = harness.cli({dir})
      os.execute("rm -rf " .. q(dir))
      assert_equal(code, 1, out)
      assert_equal(count(out, "%[901%]"), 1, "one finding, not five: " .. out)
      assert_match(out, "and 4 more", out)
      assert_match(out, "-> /usr/sbin/missing", out)
   end)

   it("never follows a target that climbs out of the scanned root with ..", function()
      -- luasec-outside/tool sits beside the scanned directory. Honouring the `..`
      -- in /../luasec-outside/tool would reach it from the scan root, and no host
      -- has /luasec-outside, so the link is dangling on any machine.
      local dir = harness.scratch_dir("rootfs_escape")
      os.execute("mkdir -p " .. q(dir .. "/img/bin") .. " " .. q(dir .. "/luasec-outside"))
      local handle = assert(io.open(dir .. "/luasec-outside/tool", "w"))
      handle:write("not lua\n")
      handle:close()
      os.execute("ln -s /../luasec-outside/tool " .. q(dir .. "/img/bin/escape"))
      local out, code = harness.cli({dir .. "/img"})
      os.execute("rm -rf " .. q(dir))
      assert_equal(code, 1, out)
      assert_match(out, "could not resolve symlink", out)
   end)

   it("finds the target under an image root nested below the scan root", function()
      local dir = harness.scratch_dir("rootfs_nested")
      os.execute("mkdir -p " .. q(dir .. "/img/usr/sbin") .. " " .. q(dir .. "/img/bin"))
      local handle = assert(io.open(dir .. "/img/usr/sbin/tool", "w"))
      handle:write("not lua\n")
      handle:close()
      os.execute("ln -s /usr/sbin/tool " .. q(dir .. "/img/bin/tool"))
      local out, code = harness.cli({dir})
      os.execute("rm -rf " .. q(dir))
      assert_equal(code, 0, out)
      assert_true(not out:find("[901]", 1, true), out)
   end)

   it("never looks for the target above the scanned root", function()
      -- The target exists one level ABOVE the directory being scanned, so a climb
      -- that did not stop at the scan root would find it.
      local dir = harness.scratch_dir("rootfs_above")
      os.execute("mkdir -p " .. q(dir .. "/usr/sbin") .. " " .. q(dir .. "/img/bin"))
      local handle = assert(io.open(dir .. "/usr/sbin/tool", "w"))
      handle:write("not lua\n")
      handle:close()
      os.execute("ln -s /usr/sbin/tool " .. q(dir .. "/img/bin/tool"))
      local out, code = harness.cli({dir .. "/img"})
      os.execute("rm -rf " .. q(dir))
      assert_equal(code, 1, out)
      assert_match(out, "could not resolve symlink", out)
   end)

   it("ignores a dangling link whose name cannot be Lua, but not a Lua-named one", function()
      local dir = tree("rootfs_names")
      os.execute("ln -s /usr/lib/libx.so " .. q(dir .. "/bin/libx.so"))
      os.execute("ln -s /usr/lib/libx.so.1.2.3 " .. q(dir .. "/bin/libx.so.1.2.3"))
      local quiet, quiet_code = harness.cli({dir})
      assert_equal(quiet_code, 0, quiet)
      assert_true(not quiet:find("[901]", 1, true), quiet)
      os.execute("ln -s /nowhere/handler.lua " .. q(dir .. "/bin/handler.lua"))
      local loud, loud_code = harness.cli({dir})
      os.execute("rm -rf " .. q(dir))
      assert_equal(loud_code, 1, loud)
      assert_match(loud, "could not resolve symlink", loud)
   end)

   it("does not read the host's file through a link when the tree has its own copy", function()
      -- /etc/hosts exists on every host this runs on, so the link resolves there;
      -- the tree holds its own etc/hosts, which is what an extracted image means.
      local dir = harness.scratch_dir("rootfs_hostfile")
      os.execute("mkdir -p " .. q(dir .. "/img/etc") .. " " .. q(dir .. "/img/bin"))
      local handle = assert(io.open(dir .. "/img/etc/hosts", "w"))
      handle:write("127.0.0.1 localhost\n")
      handle:close()
      os.execute("ln -s /etc/hosts " .. q(dir .. "/img/bin/hosts.lua"))
      local out, code = harness.cli({dir .. "/img"})
      os.execute("rm -rf " .. q(dir))
      assert_equal(code, 0, out)
      assert_true(not out:find("[901]", 1, true), "the host's /etc/hosts must not be parsed as Lua: " .. out)
   end)
end)
