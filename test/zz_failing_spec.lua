-- Entry point for `make runner-selftest`. Runs the selfcheck directory (which
-- contains exactly one failing spec) and exits with that runner's status.
package.path = "./test/?.lua;" .. package.path
local harness = require "harness"
local _, failures = harness.run({ "test/selfcheck" })
os.exit(#failures == 0 and 0 or 1)
