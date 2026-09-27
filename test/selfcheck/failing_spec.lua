-- Exists only to prove the runner reports failures and exits non-zero.
-- `make runner-selftest` runs this directory and asserts a non-zero exit.
harness.describe("intentional failure", function()
   harness.it("fails on purpose", function()
      harness.assert_equal(1, 2, "intentional")
   end)
end)
