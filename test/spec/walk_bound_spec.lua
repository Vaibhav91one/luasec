-- The bound on how much one scan root may resolve to, and the de-duplication
-- that keeps one directory from being walked twice.
--
-- -L is in walk.lua because a file behind a symlink that luasec never read is
-- the one failure this tool cannot have, and the price of -L is that a link to a
-- directory makes the walk descend into it again, once per link that names it,
-- and a link to / has no end to it. Neither half of the growth is answered by
-- taking -L back out: an invariant is not worth trading for a faster walk, and
-- the walk is now both bounded and walked once.
--
-- These are the two halves of the trade. The bound is a stated number with a
-- default no real firmware rootfs reaches, overridable so a spec can prove it
-- without creating 50,000 files. The de-duplication is of the traversal, never
-- of file content: a file that answers to two names inside one tree is reported
-- under both, because dropping one of them is a coverage hole dressed up as an
-- optimization.

local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match, assert_no_match =
   harness.assert_equal, harness.assert_true, harness.assert_match, harness.assert_no_match

local serial = 0

local function scratch_dir(tag)
   serial = serial + 1
   local dir = os.getenv("TMPDIR") or "/tmp"
   dir = dir:gsub("/$", "")
   dir = ("%s/luasec_walkbound_%s_%d_%d"):format(dir, tag, os.time(), serial)
   os.execute("mkdir -p " .. string.format("%q", dir))
   return dir
end

local function write(path, text)
   local handle = assert(io.open(path, "w"))
   handle:write(text)
   handle:close()
end

local function link(target, path)
   os.execute("ln -sfn " .. string.format("%q", target) .. " " .. string.format("%q", path))
end

local function drop(dir)
   os.execute("rm -rf " .. string.format("%q", dir))
end

local function occurrences(text, pattern)
   local _, count = text:gsub(pattern, "")
   return count
end

-- Untrusted input reaching a sink, so the file has a finding of its own: what
-- is under test here is which paths the walk read, not whether it can spot a
-- command execution.
local TAINTED = "local function ping(host)\n   os.execute(\"ping -c1 \" .. http.formvalue(host))\nend\nreturn ping\n"

-- harness.cli has no way to set an environment variable, and the bound is only
-- reachable at a limit no real tree comes near, so the CLI is run from here.
-- `env` is the whole of it: one assignment, then the same binary the other
-- specs use.
local function cli(env, args)
   local cmd = "env"
   if env then cmd = cmd .. " " .. env end
   cmd = cmd .. " ./bin/luasec"
   for _, arg in ipairs(args) do cmd = cmd .. " " .. string.format("%q", arg) end
   cmd = cmd .. " 2>&1; printf '\\n__EXIT__%d' $?"
   local pipe = assert(io.popen(cmd))
   local out = pipe:read("*a")
   pipe:close()
   local code = tonumber(out:match("__EXIT__(%d+)%s*$") or "-1")
   return (out:gsub("__EXIT__%d+%s*$", "")), code
end

describe("a symlink inside the scanned tree", function()
   it("is followed to a file, and the file behind it is analyzed", function()
      -- find's -type f matches a symlink rather than its target, so a symlinked
      -- file and a symlinked directory were both skipped: a file reachable
      -- inside the scanned tree that luasec never read, reported as a clean
      -- tree with exit 0. One entry in a firmware image is enough to hide a
      -- file that way, and this is the case that must not regress.
      local dir = scratch_dir("link_file")
      write(dir .. "/hidden.lua", TAINTED)
      link("hidden.lua", dir .. "/via_link.lua")

      local out, code = cli(nil, { dir })
      drop(dir)

      assert_match(out, "hidden%.lua",
         "the file behind a symlink is read:\n" .. out)
      assert_match(out, "709",
         "and its finding is reported:\n" .. out)
      assert_true(code ~= 0,
         "a file with a finding must not exit clean:\n" .. out)
   end)

   it("is followed to a directory outside the tree", function()
      local base = scratch_dir("link_dir")
      os.execute("mkdir -p " .. string.format("%q", base .. "/outside")
         .. " " .. string.format("%q", base .. "/tree"))
      write(base .. "/outside/x.lua", TAINTED)
      link("../outside", base .. "/tree/link")

      local out, code = cli(nil, { base .. "/tree" })
      drop(base)

      assert_match(out, "x%.lua",
         "a directory behind a symlink is walked:\n" .. out)
      assert_match(out, "709", out)
      assert_true(code ~= 0, out)
   end)

   it("does not get a directory in the tree walked a second time", function()
      -- The one that costs. Measured here on a 4,000-file tree: 1.8 s as a plain
      -- tree, 3.3 s with twenty links to one of its own directories, and every
      -- copy analyzed again. A link that names a directory the walk has already
      -- covered names no ground that is new, so the same file must be reported
      -- once, not once per link that reaches it.
      local dir = scratch_dir("link_dir_inside")
      os.execute("mkdir " .. string.format("%q", dir .. "/real"))
      write(dir .. "/real/a.lua", TAINTED)
      link("real", dir .. "/alias")

      local out, code = cli(nil, { dir })
      drop(dir)

      assert_equal(occurrences(out, "%[709%]"), 1,
         "one file behind one link, one finding:\n" .. out)
      assert_true(code ~= 0, out)
   end)

   it("is reported when it names nothing that resolves", function()
      local dir = scratch_dir("link_dangling")
      write(dir .. "/ok.lua", "local x = 1\n")
      link("nowhere", dir .. "/dangling.lua")

      local out, code = cli(nil, { dir })
      drop(dir)

      assert_match(out, "could not resolve symlink",
         "a link to nothing is ground we did not cover, not a link to skip:\n" .. out)
      assert_match(out, "901", out)
      assert_true(code ~= 0,
         "a tree with a link we could not resolve must not exit clean:\n" .. out)
   end)

   it("does not hang on a link that points back into its own tree", function()
      -- `a -> .` is the entry one line long that makes a following traversal
      -- descend into itself forever. The walk resolves a link to one physical
      -- path and walks each of those once, so this is a directory already
      -- covered rather than an unbounded descent, and the run comes back.
      local dir = scratch_dir("link_self")
      write(dir .. "/a.lua", "local x = 1\n")
      link(".", dir .. "/self")
      link("self", dir .. "/again")

      local started = os.time()
      local out, code = cli(nil, { dir })
      local elapsed = os.time() - started
      drop(dir)

      assert_no_match(out, "stack traceback", out)
      assert_true(elapsed < 30,
         ("a link to its own directory took %ds to come back:\n%s"):format(elapsed, out))
      assert_equal(occurrences(out, "resolved to more than"), 0,
         "a self-referential link is a loop to break, not a tree that grew:\n" .. out)
      assert_equal(code, 0, out)
   end)
end)

describe("a tree that resolves past the limit", function()
   it("reports the coverage gap and fails the run", function()
      -- The bound is the only thing between a firmware image and a symlink farm
      -- that costs unbounded time, and a run that stopped reading must not
      -- report the part it did read as a clean tree. Same rule as an unreadable
      -- directory: ground not covered is a 901 and a non-zero exit.
      local dir = scratch_dir("bound")
      for i = 1, 5 do write(("%s/f%d.lua"):format(dir, i), "local x = 1\n") end

      local out, code = cli("LUASEC_MAX_WALK_PATHS=2", { dir })
      drop(dir)

      assert_match(out, "901", out)
      assert_match(out, "not analyzed", out)
      assert_match(out, "resolved to more than 2",
         "the message has to name the limit the operator can change:\n" .. out)
      assert_true(code ~= 0,
         "a scan that stopped early must not exit clean:\n" .. out)
   end)

   it("is not tripped by a tree that stays under it", function()
      local dir = scratch_dir("bound_ok")
      for i = 1, 3 do write(("%s/f%d.lua"):format(dir, i), "local x = 1\n") end

      local out, code = cli("LUASEC_MAX_WALK_PATHS=100", { dir })
      drop(dir)

      assert_no_match(out, "901",
         "a tree inside the limit is a tree that was read:\n" .. out)
      assert_equal(code, 0, out)
   end)

   it("counts each scan root on its own budget", function()
      -- The bound is on what one root may resolve to, so three small roots are
      -- three small scans. A shared budget would report a coverage gap for a
      -- run that covered everything it was asked to cover.
      local base = scratch_dir("bound_roots")
      local roots = {}
      for i = 1, 3 do
         roots[i] = ("%s/r%d"):format(base, i)
         os.execute("mkdir " .. string.format("%q", roots[i]))
         write(("%s/f%d.lua"):format(roots[i], i), "local x = 1\n")
      end

      local out, code = cli("LUASEC_MAX_WALK_PATHS=2", { roots[1], roots[2], roots[3] })
      drop(base)

      assert_no_match(out, "901", out)
      assert_equal(code, 0, out)
   end)

   it("falls back to the shipped limit when the environment names a nonsense one", function()
      -- A typo in the environment must not switch the bound off, and "0" is how
      -- people spell "no limit". There is no unlimited: a value that is not a
      -- positive integer falls back to the number the tool ships, which is the
      -- direction that still costs the scan something it has to report.
      local dir = scratch_dir("bound_bad")
      write(dir .. "/f.lua", "local x = 1\n")

      for _, value in ipairs({"0", "-1", "abc", "3.5", ""}) do
         local out, code = cli("LUASEC_MAX_WALK_PATHS=" .. value, { dir })
         assert_no_match(out, "901", "limit " .. value .. ":\n" .. out)
         assert_equal(code, 0, "limit " .. value .. ":\n" .. out)
      end
      drop(dir)
   end)

   it("stops in the middle of a link's record without falling over", function()
      -- The link pass writes a directory link as four records, so a limit that
      -- runs out between the third and the fourth leaves a link the walk knows
      -- the name of and not the directory it names. Indexing that as if the
      -- record were whole takes the run down with a traceback, which is how a
      -- bound on the tree becomes an outage in the tool reading it.
      --
      -- Shaped to land there: no file inside the tree (so the file pass spends
      -- nothing), two links to files that live outside it and so cost the file
      -- pass nothing either, then a link to a directory, whose fourth record is
      -- the one the limit cuts.
      local base = scratch_dir("bound_mid_record")
      os.execute("mkdir -p " .. string.format("%q", base .. "/outside")
         .. " " .. string.format("%q", base .. "/tree/real"))
      write(base .. "/outside/a.lua", "local x = 1\n")
      write(base .. "/outside/b.lua", "local x = 1\n")
      link("../outside/a.lua", base .. "/tree/link_a")
      link("../outside/b.lua", base .. "/tree/link_b")
      link("real", base .. "/tree/link_dir")

      local out, code = cli("LUASEC_MAX_WALK_PATHS=2", { base .. "/tree" })
      drop(base)

      assert_no_match(out, "stack traceback",
         "a stream that stops mid record is not a crash:\n" .. out)
      assert_no_match(out, "attempt to", out)
      assert_match(out, "901", out)
      assert_true(code ~= 0, out)
   end)
end)

describe("a tree with no symlinks in it", function()
   it("is unaffected: every finding, no coverage gap", function()
      local dir = scratch_dir("plain")
      os.execute("mkdir -p " .. string.format("%q", dir .. "/cgi-bin"))
      write(dir .. "/tainted.lua", TAINTED)
      write(dir .. "/cgi-bin/handler", "local target = arg[1]\nos.execute(\"wget \" .. target)\n")
      write(dir .. "/token.lua", 'local API_TOKEN = "ghp_4eC39Jqklj3nR2vB8sY1wZ5"\n'
         .. "return API_TOKEN\n")

      local out, code = cli(nil, { dir })
      drop(dir)

      assert_no_match(out, "901", out)
      assert_no_match(out, "not analyzed", out)
      assert_equal(occurrences(out, "%[709%]"), 1,
         "the one file that reaches a sink is reported once:\n" .. out)
      -- Every finding the tree has, from three different rules, so a walk that
      -- lost one of them would show it here.
      assert_match(out, "tainted%.lua", out)
      assert_match(out, "handler", "an extensionless cgi-bin script is still Lua:\n" .. out)
      assert_match(out, "token%.lua", out)
      assert_match(out, "701", out)
      assert_match(out, "747", out)
      assert_equal(code, 1, out)
   end)

   it("reads every path, not only the ones in the first buffer", function()
      -- The listing is read in chunks, because reading it whole is the unbounded
      -- work the limit exists to stop. Long names make the tree cross a chunk
      -- with a few hundred files instead of a few thousand, because this is
      -- about where a path falls in the stream, not about how big the tree is.
      --
      -- Every file has a finding, so the count in the report is the count of
      -- files the walk read. A reader that loses its place between chunks keeps
      -- the first buffer and drops the rest, and that is a tree reported
      -- complete with a third of it never read.
      local dir = scratch_dir("chunks")
      -- 250 bytes a name, which is the most a filesystem here allows, so the
      -- tree crosses the reader's chunk with a couple of hundred files.
      local filler = string.rep("n", 246)
      for i = 1, 250 do write(("%s/%s%03d.lua"):format(dir, filler, i),
         "os.execute(cmd)\n") end

      local out, code = cli(nil, { dir })
      drop(dir)

      assert_equal(occurrences(out, "%[701%]"), 250,
         "every path in the stream is a file the walk read:\n" .. out)
      assert_no_match(out, "901", out)
      assert_true(code ~= 0, out)
   end)

   it("exits 0 with nothing in it", function()
      local dir = scratch_dir("plain_clean")
      write(dir .. "/clean.lua", "local x = 1\n")

      local out, code = cli(nil, { dir })
      drop(dir)

      assert_equal(code, 0, out)
      assert_no_match(out, "901", out)
   end)
end)

describe("a file that answers to two names in one tree", function()
   it("is reported at both, because dropping one would be a coverage hole", function()
      -- The deliberate decision. A hard link, or a bind mount reachable at two
      -- paths, is one inode at two names. The walk does not de-duplicate by
      -- content, so both names are read and both are reported: the cost is a
      -- repeated finding on a rare tree, and the alternative is dropping a path
      -- an operator can see and a finding they cannot otherwise get. The
      -- de-duplication above is of the traversal, not of the files.
      local dir = scratch_dir("hardlink")
      write(dir .. "/one.lua", TAINTED)
      os.execute("ln " .. string.format("%q", dir .. "/one.lua")
         .. " " .. string.format("%q", dir .. "/two.lua"))

      local out, code = cli(nil, { dir })
      drop(dir)

      assert_match(out, "one%.lua", out)
      assert_match(out, "two%.lua", out)
      assert_equal(occurrences(out, "%[709%]"), 2,
         "both names are ground we covered:\n" .. out)
      assert_true(code ~= 0, out)
   end)
end)
