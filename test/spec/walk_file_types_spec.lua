-- Which files the walk is willing to hand the parser, and the two categories it
-- refuses before it reads a byte.
--
-- #288 found that 436 of the 466 parse failures this tool reported over the
-- corpus were on files that are not Lua at all - Test::Nginx `.t` specs, shell
-- scripts, a SystemTap probe, a C lexer generator - and that two
-- `.git/packed-refs` were being read as Lua whenever an upstream branch happened
-- to be named `lua-something` at clone time. The second is the worse of the two:
-- it made the frozen measurement a function of which branches upstream had, so
-- the number could move with no code change and no diff here.
--
-- The three behaviours below are ordered the way the issue argues them, because
-- they are three different kinds of answer and only the first is a category:
--
--   1. `.git/` is never descended into, whatever it is called. A suffix list
--      enumerates the failures someone has already hit; `packed-refs` can be
--      renamed, a packfile can be any name, and every checkout has one. Adding
--      ["packed-refs"] = true would pass a test named for this issue and fix
--      nothing.
--   2. A suffix that names another language decides, and the content never gets
--      to overrule it. A `.t` file is Perl; that is not a guess.
--   3. The content sniff, for the files that have no suffix to go on, is a
--      first-line question rather than a 512-byte one.
--
-- And the direction this must not move, asserted positively rather than inferred
-- from the absence of new findings: every real `.lua` file, every Lua-shebang
-- script and every extensionless file that opens like Lua is still selected.
-- Excluding one real `.lua` file would be worse than the noise this removes.

local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match, assert_no_match =
   harness.assert_equal, harness.assert_true, harness.assert_match, harness.assert_no_match
local scratch_dir = harness.scratch_dir
local cli = harness.cli

local function write(path, text)
   local handle = assert(io.open(path, "wb"))
   handle:write(text)
   handle:close()
end

local function mkdir(path)
   os.execute("mkdir -p " .. string.format("%q", path))
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

-- Untrusted input reaching a sink, so a file that IS Lua has a finding of its
-- own. What is under test everywhere below is which paths were read, and a file
-- with no finding cannot show that.
local TAINTED = "local function ping(host)\n   os.execute(\"ping -c1 \" .. http.formvalue(host))\nend\nreturn ping\n"

-- What a Test::Nginx spec actually is: a Perl program with a vim modeline, a
-- `use` line, and the Lua it exercises inside heredocs. The Lua inside is real
-- and lua-doctor does see it through the lexical fallback - that capability is a
-- known gap, filed separately - but the file is Perl, and every one of these
-- parses as a 901/902/903 triple. The heredoc carries a real sink so the test
-- cannot pass by the file simply having nothing in it.
local NGINX_T = table.concat({
   '# vim:set ft= ts=4 sw=4 et fdm=marker:',
   '',
   'use Test::Nginx::Socket::Lua;',
   '',
   'repeat_each(2);',
   'plan tests => repeat_each() * (blocks() * 3);',
   '',
   'no_long_string();',
   'run_tests();',
   '',
   '__DATA__',
   '',
   '=== TEST 1: exec',
   '--- http_config eval: $::HttpConfig',
   'lua_code_chunk << "EOF"',
   'local target = ngx.var.arg_target',
   'os.execute("wget " .. target)',
   'EOF',
   '',
}, "\n")

-- A SystemTap probe. It opens with `function`, which the old 512-byte opener
-- list accepted, and it is not Lua: the body is C-like probe syntax.
local STAP_PROBE = "function ngx_http_lua_ctx_context(r)\n{\n   printf(\"lua\\n\");\n}\n"

-- A git packfile index: a real binary, which carries the ASCII of the branch
-- names it sorts next to the object ids it names. Built here so the assertions
-- do not depend on which branches upstream happens to have today.
local function packfile()
   return table.concat({
      "PACK\1\2\3\4", string.rep("\255\0\1\2", 40),
      "refs/remotes/origin/balancer-by-lua-2\n",
   })
end

-- A binary whose first bytes happen to be a Lua opener, and whose first 512
-- bytes contain `lua`. This is the shape the 512-byte sniff cannot see: it reads
-- an opener and stops looking, so a truncated blob, a packed format with a text
-- header, or a file a vendor wrote with a leading `return` in it is read as Lua
-- and reported as a parse failure on a file that has no Lua in it. Only the
-- bytes decide.
local function binary_that_opens_like_lua()
   return table.concat({
      "return ", string.rep("\255\0\1\2", 60), "lua-ffi.h\0\0\0",
   })
end

-- A git packed-refs index: the exact failure in the issue. Text, not binary -
-- it is git's ref listing - and whether the walk read it depended on whether a
-- branch name upstream contained the substring `lua`.
local PACKED_REFS = table.concat({
   "# pack-refs with: peeled fully-peeled sorted ",
   "8d9032298ef542aef058fa02940a6ecd9cf25423 refs/remotes/origin/0.10.21.x\n",
   "4c1e2b8ba9e0b2d9ad3b0e5f2e9a1f7d6c5b4a392 refs/heads/balancer-by-lua-2\n",
   "b1902e7f0a4c6d8e9f1a2b3c4d5e6f708192a3b4c refs/tags/v0.10.26\n",
}, "")

describe("a .git directory inside the scanned tree", function()
   it("is never descended into, so nothing under it is ever reported", function()
      -- The category, not the case. A packfile, an index and a packed-refs are
      -- all in here, under three names, plus a `.lua` file inside `.git` to
      -- prove the exclusion is of the directory and not of a suffix: a walk that
      -- excluded `.git/packed-refs` and nothing else would still read the rest.
      local dir = scratch_dir("walktypes_gitdir")
      write(dir .. "/ok.lua", TAINTED)
      mkdir(dir .. "/.git/objects/pack")
      mkdir(dir .. "/.git/hooks")
      write(dir .. "/.git/packed-refs", PACKED_REFS)
      write(dir .. "/.git/objects/pack/pack-9f2a.idx", packfile())
      write(dir .. "/.git/hooks/post-checkout.lua", TAINTED)

      local out, code = cli({ dir })
      drop(dir)

      assert_no_match(out, "%.git",
         "no finding anywhere may report a path under a .git directory:\n" .. out)
      assert_no_match(out, "901",
         "nothing under .git was parsed, so nothing there failed to parse:\n" .. out)
      assert_match(out, "ok%.lua",
         "and the Lua beside it is still read:\n" .. out)
      assert_match(out, "709", out)
      assert_true(code ~= 0, out)
   end)

   it("is not descended into when a symlink names it", function()
      -- The other way in. `find -H` does not follow this link, so the directory
      -- arrives at expand_root as a resolved path rather than as a listing; a
      -- prune inside the find would not see it and the queue would.
      local dir = scratch_dir("walktypes_gitdir_link")
      mkdir(dir .. "/.git")
      write(dir .. "/.git/packed-refs", PACKED_REFS)
      link(".git", dir .. "/elsewhere")

      local out, code = cli({ dir })
      drop(dir)

      assert_no_match(out, "%.git",
         "a link to a .git directory is still a .git directory:\n" .. out)
      assert_no_match(out, "901", out)
      assert_equal(code, 0, out)
   end)

   it("is skipped when the operator names it as the scan root", function()
      -- Silence is the right answer here and not by accident. `.git` is not
      -- ground this scan failed to cover - it is not ground - so reporting a
      -- coverage gap for it would be a false alarm, and the acceptance criterion
      -- for this issue is that no finding anywhere names a path under `.git`.
      local dir = scratch_dir("walktypes_gitdir_root")
      mkdir(dir .. "/.git")
      write(dir .. "/.git/packed-refs", PACKED_REFS)

      local out, code = cli({ dir .. "/.git" })
      drop(dir)

      assert_no_match(out, "%.git", out)
      assert_no_match(out, "901", out)
      assert_equal(code, 0, "a directory with no Lua in it is a clean tree:\n" .. out)
   end)

   it("is still descended into when its name merely ends in .git", function()
      -- The category is the component, not the spelling. A firmware package can
      -- carry a directory called `pkg.git` or `mylua.git` holding real Lua, and
      -- dropping it would be the same class of error this issue is about.
      local dir = scratch_dir("walktypes_gitish")
      mkdir(dir .. "/vendor/pkg.git")
      write(dir .. "/vendor/pkg.git/handler.lua", TAINTED)

      local out, code = cli({ dir })
      drop(dir)

      assert_match(out, "handler%.lua",
         "a directory merely named like one is ordinary source:\n" .. out)
      assert_match(out, "709", out)
      assert_true(code ~= 0, out)
   end)
end)

describe("a file whose suffix names another language", function()
   it("is not Lua because the suffix says so, whatever the content opens with", function()
      -- The content of a Test::Nginx spec is 50 lines of Lua in heredocs, and
      -- the old sniff read the first 512 bytes looking for an opener, so it
      -- found `lua` in `use Test::Nginx::Socket::Lua` and read the whole file.
      -- One `.t` file is 901 + 902 + 903 and none of the three is information.
      local dir = scratch_dir("walktypes_t")
      write(dir .. "/000-sanity.t", NGINX_T)

      local out, code = cli({ dir })
      drop(dir)

      assert_no_match(out, "sanity%.t",
         "a .t file is Perl; the walk must not claim it is Lua:\n" .. out)
      assert_no_match(out, "901", out)
      assert_no_match(out, "902", out)
      assert_no_match(out, "903", out)
      assert_equal(code, 0, "a tree with nothing to read exits clean:\n" .. out)
   end)

   it("is not Lua for a SystemTap probe, which opens with `function`", function()
      -- `^function%s` was an opener, and a probe file opens with `function`. The
      -- probe is named ngx_lua.stp, so the suffix was the only thing that could
      -- have saved it, and the suffix was not consulted.
      local dir = scratch_dir("walktypes_stp")
      write(dir .. "/ngx_lua.stp", STAP_PROBE)

      local out, code = cli({ dir })
      drop(dir)

      assert_no_match(out, "ngx_lua%.stp", out)
      assert_no_match(out, "901", out)
      assert_equal(code, 0, out)
   end)

   it("is not Lua for a makefile, whatever suffix the distribution gave it", function()
      -- Makefile and GNUmakefile were already in the not-Lua names. A
      -- distribution that ships Makefile.dist, Makefile.am or Makefile.in
      -- defeats an exact-match table, so the whole makefile family is one name.
      local dir = scratch_dir("walktypes_makefile")
      write(dir .. "/makefile.dist", "#-----------\n# Distribution makefile for lua-resty-core\nDIST = resty\n")
      write(dir .. "/Makefile.am", "# Makefile.am for lua-resty-core\nSUBDIRS = src\n")

      local out, code = cli({ dir })
      drop(dir)

      assert_no_match(out, "makefile%.dist", out)
      assert_no_match(out, "Makefile%.am", out)
      assert_no_match(out, "901", out)
      assert_equal(code, 0, out)
   end)
end)

describe("a file with no suffix the walk knows", function()
   it("is not Lua when its shebang names another interpreter", function()
      -- `#!/bin/sh`, and the first 512 bytes mention lua because the script
      -- copies a file called luasocket.cat.tmp. The old rule asked whether those
      -- 512 bytes contain `lua` at all, which is not a question about the file.
      local dir = scratch_dir("walktypes_shebang_other")
      write(dir .. "/cat", "#!/bin/sh\necho Content-type: text/plain\ncat /tmp/luasocket.cat.tmp\n")

      local out, code = cli({ dir })
      drop(dir)

      assert_no_match(out, "/cat:", "a shell script is not Lua:\n" .. out)
      assert_no_match(out, "901", out)
      assert_equal(code, 0, out)
   end)

   it("is Lua when its shebang names a Lua interpreter", function()
      -- The direction this must not move. OpenResty and LuCI ship their entry
      -- points with no suffix at all - /usr/sbin/luci-splash, cgi-bin/luci,
      -- /usr/bin/ff_olsr_watchdog - and they are real findings in the corpus. A
      -- tighter sniff that dropped them would be a far worse defect than the
      -- 436 parse failures this issue removes.
      local dir = scratch_dir("walktypes_shebang_lua")
      write(dir .. "/ff_olsr_watchdog",
         "#!/usr/bin/lua\nlocal config = {cmd = \"/usr/bin/olsr -n\"}\nos.execute(config.cmd)\n")

      local out, code = cli({ dir })
      drop(dir)

      assert_match(out, "ff_olsr_watchdog", out)
      assert_match(out, "701", out)
      assert_true(code ~= 0, out)
   end)

   it("is Lua when an env shebang names a Lua interpreter", function()
      local dir = scratch_dir("walktypes_shebang_env")
      write(dir .. "/find-connect-limit", "#!/usr/bin/env lua\nos.execute(cmd)\n")

      local out, code = cli({ dir })
      drop(dir)

      assert_match(out, "find%-connect%-limit", out)
      assert_match(out, "701", out)
      assert_true(code ~= 0, out)
   end)

   it("is Lua when it opens like Lua and has no shebang at all", function()
      -- The opener list is the third question and it must keep answering yes:
      -- this is the extensionless handler a firmware image drops in cgi-bin, and
      -- nothing about it declares what it is except its first line.
      local dir = scratch_dir("walktypes_opener")
      write(dir .. "/status", "local socket = require \"socket\"\nos.execute(socket.tcp())\n")

      local out, code = cli({ dir })
      drop(dir)

      assert_match(out, "/status:", out)
      assert_match(out, "701", out)
      assert_true(code ~= 0, out)
   end)

   it("is Lua when it opens with a Lua comment, as a config table does", function()
      -- `.luacov`, `.luacheckrc` and a dozen other configuration files are Lua
      -- and are not named *.lua: a `--` comment over a `return { ... }` table.
      -- The opener list is what catches them, and this one opens with a comment
      -- rather than a keyword.
      local dir = scratch_dir("walktypes_comment_opener")
      write(dir .. "/defaults", "-- firmware defaults\n"
         .. "local config = {cmd = \"/bin/ping\"}\n"
         .. "config.ping = function() os.execute(config.cmd) end\nreturn config\n")

      local out, code = cli({ dir })
      drop(dir)

      assert_match(out, "/defaults:", out)
      assert_match(out, "701", out)
      assert_true(code ~= 0, out)
   end)
end)

describe("looks_like_lua", function()
   it("accepts a configuration file that opens with a Lua comment", function()
      -- The shape above with nothing in it that reaches a sink, so the CLI would
      -- say nothing at all and the walk would be invisible. Asserted at the seam.
      local walk = require "luadoctor.cli.walk"
      local dir = scratch_dir("walktypes_luacov")
      local path = dir .. "/.luacov"
      write(path, "-- luacov configuration\nreturn { statsfile = \"luacov.stats.out\" }\n")

      local answer = walk.looks_like_lua(path)
      drop(dir)

      assert_equal(answer, true, "a Lua table with no suffix is still Lua")
   end)
   it("rejects a binary that contains the word lua in its first 512 bytes", function()
      -- The acceptance criterion of #288, asserted against the seam itself rather
      -- than inferred from a corpus: today the answer is true for any file whose
      -- first 512 bytes happen to contain `lua`, which is what made
      -- corpus/*/.git/packed-refs a function of upstream branch names.
      local walk = require "luadoctor.cli.walk"
      local dir = scratch_dir("walktypes_binary")
      local path = dir .. "/pack-9f2a.idx"
      write(path, binary_that_opens_like_lua())

      local answer = walk.looks_like_lua(path)
      drop(dir)

      assert_equal(answer, false,
         "a binary that happens to contain `lua` is not a Lua file")
   end)

   it("rejects a packed-refs index whose branch names contain lua", function()
      -- The same file as it actually is in the corpus today: text, with `lua` in
      -- a branch name. This one is not binary, so the byte check cannot catch it
      -- and the first-line rule has to: a git ref listing opens with a `#`
      -- comment, and `#` is not how Lua opens.
      local walk = require "luadoctor.cli.walk"
      local dir = scratch_dir("walktypes_packed_refs")
      local path = dir .. "/packed-refs"
      write(path, PACKED_REFS)

      local answer = walk.looks_like_lua(path)
      drop(dir)

      assert_equal(answer, false,
         "which branches upstream had must not decide what this tool reads")
   end)

   it("accepts a real .lua file, whose suffix decides before any content is read", function()
      -- The other direction, and the one that matters most: a file named *.lua
      -- is Lua whatever it contains, including a shebang for another language
      -- and a NUL byte in a comment. Tightening the sniff must not reach this.
      local walk = require "luadoctor.cli.walk"
      local dir = scratch_dir("walktypes_real_lua")
      local path = dir .. "/probe.lua"
      write(path, "#!/bin/sh\n-- a file that is named .lua is Lua\nlocal x = 1\nreturn x\n")

      local answer = walk.looks_like_lua(path)
      drop(dir)

      assert_equal(answer, true,
         "a .lua file stays selected whatever its first line looks like")
   end)
end)

describe("a tree that mixes all of it", function()
   it("reports the Lua and nothing else", function()
      -- The whole issue in one scan, and the assertion that has to hold in both
      -- directions at once: the four files that are Lua are read and reported,
      -- the five that are not produce no finding and no coverage gap.
      local dir = scratch_dir("walktypes_mixed")
      write(dir .. "/handler.lua", TAINTED)
      mkdir(dir .. "/cgi-bin")
      write(dir .. "/cgi-bin/report", "#!/usr/bin/lua\nos.execute(arg[1])\n")
      write(dir .. "/000-sanity.t", NGINX_T)
      write(dir .. "/ngx_lua.stp", STAP_PROBE)
      write(dir .. "/makefile.dist", "#-----\n# makefile for lua-resty-core\nDIST = resty\n")
      mkdir(dir .. "/.git")
      write(dir .. "/.git/packed-refs", PACKED_REFS)

      local out, code = cli({ dir })
      drop(dir)

      assert_match(out, "handler%.lua", "a .lua file is still read:\n" .. out)
      assert_match(out, "cgi%-bin/report", "a Lua shebang is still read:\n" .. out)
      assert_equal(occurrences(out, "%[709%]"), 1,
         "the one file whose taint reaches a sink is reported once:\n" .. out)
      assert_equal(occurrences(out, "%[701%]"), 1,
         "and the one that only reaches the sink is reported once:\n" .. out)
      assert_no_match(out, "%.git", out)
      assert_no_match(out, "sanity%.t", out)
      assert_no_match(out, "ngx_lua%.stp", out)
      assert_no_match(out, "makefile%.dist", out)
      assert_no_match(out, "901",
         "nothing that was not read is reported as unreadable:\n" .. out)
      assert_equal(code, 1, out)
   end)
end)