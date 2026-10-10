local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match, assert_no_match = harness.assert_equal,
   harness.assert_true, harness.assert_match, harness.assert_no_match

-- The corpus is the denominator of the project's central measurement, and it is
-- built by a script that needs the network while the measurement does not. Those
-- two facts are the whole problem: `make precision` will run over whatever
-- happens to be under corpus/, count it, compare the counts to
-- scripts/precision-golden.lua, and pass - on a corpus that lost half its
-- repositories, or one whose pinned checkouts were moved to a different commit.
--
-- A count is a weak witness for "the corpus is what we said it is". Two of the
-- failures this gate exists for do not move a count at all:
--
--   * a pinned entry at another revision has exactly the same number of .lua
--     files and different code in them, so the frozen numbers describe a tree
--     that is no longer the tree;
--   * an entry that cloned into an empty working tree produces a smaller number
--     that reads exactly like a rule change, and blessing it is how the frozen
--     figures drifted before (#258, #273).
--
-- scripts/clone-corpus.sh --verify is the answer to both, and these cases are
-- what stops it decaying into a function that always returns 0. Each builds a
-- scratch corpus, breaks one thing, and asserts the failure is named. A verify
-- that cannot fail on a corpus it should reject is worse than none, because
-- `make precision` would then trust it.

local SCRIPT = "scripts/clone-corpus.sh"

-- The OpenResty-profile entries this issue added. Named here rather than
-- discovered, because "the list has six members" and "the six members are the
-- right six" are different claims and only the second one is worth a gate.
local OPENRESTY = {
   "lua-resty-core", "luasocket", "lua-resty-jwt",
   "lua-cjson", "lua-nginx-module", "lua-resty-lock",
}

-- ---------------------------------------------------------------- helpers

-- Run clone-corpus.sh in one of its modes; returns combined output, exit code.
local function script(...)
   local quoted = {}
   for _, a in ipairs({...}) do
      quoted[#quoted + 1] = string.format("%q", a)
   end
   local cmd = "bash " .. SCRIPT .. " " .. table.concat(quoted, " ")
      .. " 2>&1; printf '\\n__EXIT__%d' $?"
   local pipe = assert(io.popen(cmd))
   local out = pipe:read("*a")
   pipe:close()
   local code = tonumber(out:match("__EXIT__(%d+)%s*$") or "-1")
   return (out:gsub("__EXIT__%d+%s*$", "")), code
end

-- What clone-corpus.sh declares, as {name = {rev = ..., min_lua = ..., what = ...}}
-- in declaration order. The script's own list is the source: a second copy of it
-- here is a second thing to forget to update, which is the failure mode of every
-- count in this repo.
local function declared()
   local out, code = script("--list")
   assert_equal(code, 0, "--list exits non-zero:\n" .. out)
   local entries, order = {}, {}
   for line in out:gmatch("[^\n]+") do
      if line:match("^>>") or line:match("^%s*$") then
         error("--list also cloned something. Output:\n" .. out)
      end
      local name, rev, min_lua, what =
         line:match("^([^|]*)|([^|]*)|([^|]*)|(.*)$")
      assert_true(name ~= nil, "--list line is not name|rev|min_lua|what: " .. line)
      order[#order + 1] = name
      entries[name] = {rev = rev, min_lua = tonumber(min_lua) or -1, what = what}
   end
   assert_true(#order > 0, "--list declared no entries at all")
   entries.__order = order
   return entries
end

-- A scratch corpus root. `fill` is called as fill(name, dir) for every declared
-- entry once its directory exists; pass nil for `fill` to leave the directories
-- alone, and false to not create them at all, which is the "the checkout is not
-- there" case rather than the "the checkout is there and is empty" one. They are
-- different failures and the message an operator gets has to tell them apart.
local function scratch_root(tag, fill, make_dirs)
   local dir = harness.scratch_dir(tag)
   local entries = declared()
   if make_dirs ~= false then
      os.execute(("mkdir -p %q"):format(dir .. "/corpus"))
      for _, name in ipairs(entries.__order) do
         local entry = dir .. "/corpus/" .. name
         os.execute(("mkdir -p %q"):format(entry))
         if fill then fill(name, entry) end
      end
   end
   return dir .. "/corpus", entries
end

local function one_lua(entry)
   local handle = assert(io.open(entry .. "/only.lua", "w"))
   handle:write("return 1\n")
   handle:close()
end

local function cleanup(dir)
   os.execute(("rm -rf %q"):format(dir))
end

-- A git checkout at one commit, standing in for a real corpus entry.
local function git_checkout_at(entry)
   one_lua(entry)
   local function git(...)
      -- os.execute returns true on success, or nil plus the failing status.
      local ok = os.execute(("cd %q && git %s >/dev/null 2>&1"):format(entry, ...))
      assert_true(ok, "could not build a test checkout: git " .. table.concat({...}))
   end
   git("init -q")
   git("config user.email corpus@spec")
   git("config user.name corpus")
   git("add only.lua")
   git("commit -q -m pinned")
end

-- ---------------------------------------------------------------- the spec

describe("what the corpus is declared to hold", function()
   it("includes the OpenResty entries, each with the version it is pinned at", function()
      local entries = declared()
      for _, name in ipairs(OPENRESTY) do
         local entry = assert(entries[name],
            SCRIPT .. " no longer declares " .. name .. ", so the openresty profile is "
            .. "back to being unmeasured. The corpus and docs/precision.md both record it")
         assert_true(entry.min_lua >= 1,
            name .. " is declared with a floor of " .. entry.min_lua ..
            " .lua files, so a checkout that cloned nothing would pass verification")
         assert_true(entry.what:match("%d") ~= nil,
            name .. " is declared without saying which release it is pinned at; the entry "
            .. "reads as `" .. entry.what .. "`")
      end
   end)

   it("pins every OpenResty entry to a revision rather than a branch", function()
      local entries = declared()
      for _, name in ipairs(OPENRESTY) do
         local rev = assert(entries[name], name .. " is not declared at all").rev
         assert_true(rev:match("^%x+$") ~= nil and #rev == 40,
            name .. " is pinned at `" .. tostring(rev) .. "`, which is not a 40-character "
            .. "commit sha. A measurement against a moving branch is not a measurement")
      end
   end)

   it("gives every declared entry a floor and a description", function()
      -- The floor is what makes a silently-empty checkout loud. An entry with no
      -- floor contributes no check at all, so the entry exists in the list and
      -- in nobody's failure output.
      local entries = declared()
      for _, name in ipairs(entries.__order) do
         local entry = entries[name]
         assert_true(entry.min_lua >= 0,
            name .. " declares a floor of " .. tostring(entry.min_lua) ..
            ", which is not a number of .lua files")
         assert_true(#entry.what > 10,
            name .. " is declared with no description, so a failure naming it says nothing "
            .. "about what a reader lost")
      end
   end)
end)

describe("verifying the corpus before measuring it", function()
   it("fails, by name, on an entry that is not on disk", function()
      local root = scratch_root("corpus_missing", nil, false)
      local out, code = script("--verify", root)

      assert_true(code ~= 0,
         "verifying a corpus with nothing in it passed. This is the failure that lets "
         .. "`make precision` measure a tree that is not the corpus:\n" .. out)
      assert_match(out, "does not exist", "the failure does not say what is wrong:\n" .. out)
      for _, name in ipairs(OPENRESTY) do
         -- Plain find, not a pattern: `lua-resty-core` is a Lua pattern that
         -- does not match the string "lua-resty-core", because `-` is a lazy
         -- quantifier. Every corpus entry but one has a hyphen in its name.
         assert_true(out:find(name, 1, true) ~= nil,
            "the failure does not name " .. name .. ", so an operator is told a count moved "
            .. "and not which checkout went missing:\n" .. out)
      end
      cleanup(root)
   end)

   it("fails, by name, on an entry that is present but holds no Lua", function()
      local root = scratch_root("corpus_empty", nil)
      local out, code = script("--verify", root)

      assert_true(code ~= 0,
         "verifying a corpus of empty directories passed. Re-measuring here would give a "
         .. "smaller number that reads exactly like a rule change:\n" .. out)
      assert_match(out, "%.lua files, expected at least",
         "the failure does not report the count against the floor:\n" .. out)
      assert_no_match(out, "openwrt%-packages holds 0",
         "an entry declared to contribute no .lua is being held to a floor it cannot meet:\n" .. out)
      cleanup(root)
   end)

   it("fails, by name, on a pinned entry sitting at another revision", function()
      -- The one no count can catch: the same number of files, different code.
      local target = OPENRESTY[1]
      local root, entries = scratch_root("corpus_drift", function(name, entry)
         if name == target then
            git_checkout_at(entry)
         else
            one_lua(entry)
         end
      end)
      local out, code = script("--verify", root)
      local pinned = entries[target].rev

      assert_true(code ~= 0,
         "verifying a corpus whose pinned entry had been moved passed, and the frozen "
         .. "numbers now describe a tree that is not on disk:\n" .. out)
      assert_match(out, "not the pinned " .. pinned,
         "the failure does not name the pin it expected:\n" .. out)
      cleanup(root)
   end)

   it("fails, by name, on a pinned entry whose checkout cannot be checked at all", function()
      -- A directory with the right files and no git metadata: the count is right
      -- and nothing can be said about whether the code is.
      local root = scratch_root("corpus_nogit", function(name, entry)
         if name == OPENRESTY[2] then one_lua(entry) else git_checkout_at(entry) end
      end)
      local out, code = script("--verify", root)

      assert_true(code ~= 0,
         "verifying a corpus with an unverifiable pin passed:\n" .. out)
      assert_match(out, "no %.git, so its pin",
         "the failure does not say the pin could not be checked:\n" .. out)
      cleanup(root)
   end)

   it("is what `make precision` runs before it runs the analyzer", function()
      -- Without this the verify above proves nothing about the measurement: it
      -- would be a mode nothing ever calls. Read as text, because that is the
      -- only place the wiring is written down, and the same reason
      -- precision_spec.lua reads docs/precision.md.
      local handle = assert(io.open("Makefile", "r"), "cannot read Makefile")
      local text = handle:read("*a")
      handle:close()

      local start = assert(text:find("\nprecision:", 1, true),
         "the Makefile has no `precision` recipe to check")
      local recipe = text:sub(start, text:find("\n%.PHONY: ci%-verify", start) or (#text + 1))

      local verify_at = recipe:find("%-%-verify")
      local analyze_at = recipe:find("bin/lua%-doctor")
      assert_true(verify_at ~= nil,
         "the precision recipe never calls " .. SCRIPT ..
         " --verify, so a corpus that lost a checkout is still measured and still counted")
      assert_true(analyze_at ~= nil, "the precision recipe does not run the analyzer at all")
      assert_true(verify_at < analyze_at,
         "the precision recipe runs the analyzer before it verifies the corpus, so a corpus "
         .. "that is not the corpus still produces a measurement")
   end)
end)