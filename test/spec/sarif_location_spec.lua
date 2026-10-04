-- Where a SARIF result points.
--
-- A SARIF `artifactLocation.uri` is a promise: a consumer resolves it and opens
-- the file. A directory breaks that promise - GitHub code scanning and every
-- other consumer that takes the uri fails to resolve it - so the one finding
-- that says "this run did not fully read your firmware" is the one finding a
-- reader cannot get to.
--
-- The invariant these specs hold: a SARIF result either names a file a consumer
-- can open, or names nothing.

local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match, assert_no_match =
   harness.assert_equal, harness.assert_true, harness.assert_match, harness.assert_no_match

local function q(text) return string.format("%q", text) end

-- An extracted image holding `n` links that resolve to nothing inside it. Two
-- or more is the load-bearing number: one link reports its own path and is
-- already a place, and it is the aggregate over several that had nowhere to
-- point.
local function image_with_dangling_links(tag, n)
   local dir = harness.scratch_dir(tag)
   os.execute("mkdir -p " .. q(dir .. "/lib"))
   for i = 1, n do
      os.execute(("ln -s /usr/lib/lua/absent%d.lua %s"):format(i, q(dir .. ("/lib/link%d.lua"):format(i))))
   end
   return dir
end

local function image_with_two_dangling_links(tag)
   return image_with_dangling_links(tag, 2)
end

local function drop(dir) os.execute("rm -rf " .. q(dir)) end

describe("a coverage gap over an image with several unresolvable symlinks", function()
   it("is a SARIF result with no location, because the directory it names is not a file", function()
      -- The aggregate has no honest place: the links that failed are different
      -- files, and the root is a container. Emitting it as an artifactLocation
      -- hands every consumer a uri that resolves to nothing.
      local dir = image_with_two_dangling_links("sarif_location_gap")
      local out, code = harness.cli({"--format", "sarif", dir})
      drop(dir)

      assert_match(out, '"ruleId": "901"', out)
      assert_no_match(out, "artifactLocation",
         "a SARIF result must not name a file it cannot open:\n" .. out)
      assert_true(code ~= 0,
         "a run that did not read everything still has to fail:\n" .. out)
   end)
end)

describe("the same coverage gap read as plain text", function()
   it("prints the finding without a `directory:1:1` prefix, because that is not a place", function()
      -- Plain output is where an operator reads first, and `dir:1:1` is the same
      -- false promise as the SARIF uri: it is formatted so an editor or a `vim +
      -- file:line` will try to open it, and there is nothing at that path a
      -- reader can be sent to. It has to agree with SARIF, which names no
      -- location, rather than disagreeing with it while reporting the same
      -- finding.
      local dir = image_with_two_dangling_links("sarif_location_plain")
      local out, code = harness.cli({dir})
      drop(dir)

      assert_match(out, "%[901%]", out)
      -- Not `%q` here: that wraps the path in double quotes, which is right for
      -- a shell argument and wrong inside a Lua pattern.
      assert_no_match(out, "^" .. dir .. ":1:1",
         "plain must not offer the scanned directory as a file location:\n" .. out)
      assert_true(code ~= 0, out)
   end)
end)

describe("a finding that is about a place in the scanned tree", function()
   it("keeps its artifactLocation, because dropping it would leave it unaddressed", function()
      -- The other half of the fix. Unanchoring a directory must not turn into
      -- unanchoring everything: a finding in a file a consumer can open is the
      -- case SARIF is for, and losing that location would make every result in
      -- the report unclickable to repair one that was never clickable.
      local out = harness.cli({"--format", "sarif", "test/fixtures/tainted_exec/handler.lua"})
      assert_match(out, '"ruleId": "709"', out)
      assert_match(out, '"uri": "test/fixtures/tainted_exec/handler%.lua"', out)
      assert_match(out, '"startLine": 3',
         "the region is still the line the sink is on:\n" .. out)
   end)
end)

describe("the aggregate gap, now that it carries no location", function()
   it("names every link it covers in its message, so nothing was lost by dropping the uri", function()
      -- The reason an aggregate is still worth publishing when it cannot be
      -- clicked: the message is the whole finding. If a reader only has the
      -- message left, every link that could not be resolved has to be in it -
      -- which is what makes it a fix list rather than a shrug.
      local dir = image_with_dangling_links("sarif_location_names", 4)
      local out = harness.cli({"--format", "sarif", dir})
      drop(dir)

      for i = 1, 4 do
         assert_match(out, "lib/link" .. i .. "%.lua",
            "the message has to name link " .. i .. " as well:\n" .. out)
      end
   end)
end)

describe("a scan that stopped early at the walk bound", function()
   it("is a SARIF result with no location either, because it is anchored to the root too", function()
      -- The same defect by a second route, found while fixing the first: a tree
      -- that resolves past the bound is reported against the scan root as well,
      -- so a fix written for dangling symlinks alone would have left this one
      -- emitting a uri no consumer can open. The rule is about what a location
      -- is, not about which finding used to get it wrong.
      local dir = harness.scratch_dir("sarif_location_bound")
      for i = 1, 5 do
         local handle = assert(io.open(dir .. "/f" .. i .. ".lua", "w"))
         handle:write("local x = 1\n")
         handle:close()
      end
      local out, code = harness.cli({"--format", "sarif", dir}, {env = "LUASEC_MAX_WALK_PATHS=2"})
      drop(dir)

      assert_match(out, '"ruleId": "901"', out)
      assert_no_match(out, "artifactLocation",
         "a SARIF result must not name a file it cannot open:\n" .. out)
      assert_match(out, "resolved to more than 2",
         "the message still says what was not read:\n" .. out)
      assert_true(code ~= 0, out)
   end)
end)

describe("the same coverage gap as JSON", function()
   it("is the same one finding with the same message, and still records what it covered", function()
      -- The three formats have to agree. What none of them may decide
      -- separately is whether the gap exists or what it says, so this asserts
      -- that the JSON document carries the one finding plain and SARIF printed.
      --
      -- `file` stays, and that is deliberate: in JSON it is the record of what
      -- the run was given and the key the baseline compares on, not a claim
      -- that anything opens it. Nothing in a JSON document is navigable, so
      -- nothing there is the false promise the SARIF uri was.
      local dir = image_with_two_dangling_links("sarif_location_json")
      local out, code = harness.cli({"--format", "json", dir})
      drop(dir)

      local _, count = out:gsub('"code": "901"', "")
      assert_equal(count, 1, "the same single gap, not one per format:\n" .. out)
      assert_match(out, '"file": "' .. dir .. '"',
         "json still records the root the run could not fully cover:\n" .. out)
      for _, link in ipairs({"lib/link1.lua", "lib/link2.lua"}) do
         assert_match(out, link, "the message names " .. link .. " as well:\n" .. out)
      end
      assert_true(code ~= 0, out)
   end)
end)
