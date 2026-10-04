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

-- An extracted image holding two links that resolve to nothing inside it. Two
-- is the load-bearing number: one link reports its own path and is already a
-- place, and it is the aggregate over several that had nowhere to point.
local function image_with_two_dangling_links(tag)
   local dir = harness.scratch_dir(tag)
   os.execute("mkdir -p " .. q(dir .. "/lib"))
   os.execute("ln -s /usr/lib/lua/absent.lua " .. q(dir .. "/lib/a.lua"))
   os.execute("ln -s /usr/lib/lua/missing.lua " .. q(dir .. "/lib/b.lua"))
   return dir
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