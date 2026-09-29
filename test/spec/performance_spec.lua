-- Guard against the analysis going super-linear in the size of its input.
--
-- Each spec measures a RATIO t(4N)/t(N) so the bound is independent of the
-- machine running the suite: an analysis that is linear in input size gives a
-- ratio near 4, one that is quadratic near 16. The threshold is deliberately
-- loose (8, i.e. "between linear and quadratic"): this is a tripwire for a
-- regression, not a benchmark, and the worst noise this machine has shown
-- between two runs of the same size is enough to paint a tight bound red.
--
-- `best_of` takes the minimum of two runs at a size before dividing, so a
-- single slow run - the OS deciding to page, a background build, whatever -
-- pulls the numerator up but never the denominator. `collectgarbage("collect")`
-- runs between samples so the allocator from one run does not land inside the
-- next, which is the single biggest source of noise this machine shows.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true = harness.assert_true

local api = require "luasec.api"

-- The minimum of `runs` timed passes at `src, opts`, in seconds. os.clock()
-- measures CPU time of this process, so it is not moved by other processes the
-- way wall-clock is - but a GC kick or a page fault still spikes a single
-- sample, hence the minimum over two.
local function best_of(src, opts, runs)
   local best = 1 / 0
   for _ = 1, runs do
      collectgarbage("collect")
      local started = os.clock()
      api.check_source(src, opts)
      local elapsed = os.clock() - started
      if elapsed < best then best = elapsed end
   end
   return best
end

-- Two timed passes are enough to shake clock noise off the minimum on this
-- machine: a single GC or page-fault spike is dropped, and the floor of 0.05 s
-- keeps the smaller size out of the rounding band. Three runs is more robust
-- but roughly doubles the file's runtime, which this repo's 15 s budget does
-- not leave room for across all three specs.
local RUNS = 2

-- t(4N)/t(N) from a generator parameterised by a single linear size N. A
-- linear implementation lands near 4; a quadratic one near 16. The threshold is
-- loose so machine noise - which this machine shows as a >2x spread inside one
-- configuration - cannot paint a green line red, while an order-of-magnitude
-- regression still trips it. The floor of 0.05 s keeps clock rounding noise
-- out of the smaller sample.
local function assert_linear(gen, n, opts, label)
   local initial_n = n
   local t_n = best_of(gen(n), opts, RUNS)
   while t_n < 0.05 and n < 64 * initial_n do
      n = n * 2
      t_n = best_of(gen(n), opts, RUNS)
   end

   assert_true(n < 64 * initial_n or t_n >= 0.05,
      label .. ": t(N) was " .. t_n .. " s at N=" .. n .. "; noise dominates below 0.05 s")

   local t_4n = best_of(gen(4 * n), opts, RUNS)
   local ratio = t_4n / t_n
   assert_true(ratio < 8,
      label .. ": t(4N)/t(N) at N=" .. n .. " = " .. t_4n .. "/" .. t_n
         .. " = " .. ratio .. " is not linear (< 8)")
end

describe("747 cursor check scales linearly with cursor assignments and uses", function()
   it("t(4N)/t(N) < 8 on N cursor assignments and N uses", function()
      -- The 747 cursor check is asked once per use of a table field, and the
      -- answer depends on every value assigned to that field. f5abb2b fixed a
      -- walk over those values inside the per-use loop (32,000 assignments
      -- and 32,000 uses took 109 s where the build before took 5 s); the fix
      -- records two booleans per field in a pre-pass and answers each use in
      -- O(1). This fixture scales assignments and uses together, so a walk
      -- that creeps back inside the per-use loop shows as a ratio near 16.
      --
      -- It does not reproduce f5abb2b itself: run against 446f086, the build
      -- before that fix, this spec passes. That regression's exact shape is
      -- not recorded, and above ~4,000 lines the file is analysed
      -- approximately (904), which hides it. This is a guard for the class,
      -- not a replay of the instance.
      local function lattice(n)
         local lines = {"local t = {}", 'local cur = require("uci").cursor()'}
         for _ = 1, n do lines[#lines + 1] = "t.x = {}" end
         for _ = 1, n do lines[#lines + 1] = 't.x:set("s", "k", "v")' end
         lines[#lines + 1] = 't.x:set("system", "root_password", "R00tPassw0rd-2024")'
         return table.concat(lines, "\n")
      end

      assert_linear(lattice, 250, {std = "+openwrt+luci"}, "747 cursor lattice")
   end)
end)

describe("suppression directives scale linearly with directive count", function()
   it("t(4N)/t(N) < 8 on N suppression directives with finding count fixed", function()
      -- Guards the regression fixed in 1b3c58b: `open_at` scanned the whole
      -- directive list once per suppression, and the suppression pass ran it
      -- once per finding per suppression: O(F*D^2). 2,000 suppression lines
      -- against 1,600 findings took 171 s where the build before the scoping
      -- fix took 0.9 s, and --max-nodes did not bound it, because a rule that
      -- raises is caught rather than skipped.
      --
      -- The fix is one pass that fills a prefix-depth array before any finding
      -- is consulted, so the per-finding cost is O(1) in the directive count
      -- once the applicable directives are known. This fixture holds the finding
      -- count fixed (20 lines) and scales only the directive count with N, so
      -- the ratio is ~4 on the linear fix and far higher (quadratic in D) when
      -- the per-finding scan returns: the threshold of 8 is a loose tripwire,
      -- not a benchmark of the constant. Run against 7e159bd, the build before
      -- that fix, this spec fails with a ratio of 16.6.
      --
      -- Scaling D and F together is still quadratic today: `finalize` scans
      -- every directive once per finding, O(F*D). That is #53, and its spec
      -- belongs with its fix.
      local FINDING_COUNT = 20

      local function with_suppressions(n)
         local lines = {}
         for _ = 1, n do lines[#lines + 1] = "-- luasec: ignore 701" end
         for _ = 1, FINDING_COUNT do lines[#lines + 1] = "os.execute(cmd)" end
         return table.concat(lines, "\n")
      end

      assert_linear(with_suppressions, 500, {}, "suppression directives")
   end)
end)

describe("ordinary code scales linearly with its size", function()
   it("t(4N)/t(N) < 8 on plain functions and locals", function()
      -- Guards the general case: analysis of ordinary Lua with no findings
      -- must not hide a quadratic in a path ordinary code exercises for the
      -- first time. Every unit here is a distinct local + function + table
      -- entry, so a 4x input is 4x the syntactic units and 4x the work on a
      -- linear implementation.
      --
      -- There is no single past regression to cite for this one by number, but
      -- the lattice and suppression cases above are both instances of a scan
      -- that crept back inside a per-item loop; this pins the general shape so
      -- the same mistake on an ordinary code path is caught before it ships.
      -- The threshold is the same loose 8: the 0.05 s floor keeps clock noise
      -- out, and the ratio bounds the growth class, not the constant.
      local function plain(n)
         local lines = {"local t = {}"}
         for i = 1, n do
            lines[#lines + 1] = "local function f" .. i .. "(a, b, c)"
            lines[#lines + 1] = "  local x = a * b + c - a"
            lines[#lines + 1] = "  local y = x * 2 + b"
            lines[#lines + 1] = "  local z = y - x + c * 3"
            lines[#lines + 1] = "  return z + a"
            lines[#lines + 1] = "end"
            lines[#lines + 1] = "t[" .. i .. "] = f" .. i
         end
         return table.concat(lines, "\n")
      end

      assert_linear(plain, 300, {}, "ordinary code")
   end)
end)
