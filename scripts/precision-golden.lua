-- The frozen corpus measurement.
--
-- docs/precision.md is this number written out in prose, and the prose has been
-- wrong three times: each time the headline was edited by hand and the per-code
-- table below it was not. test/spec/precision_spec.lua stops those two from
-- disagreeing with each other, which is not the same thing as either being
-- right - a rule that changes what the tool finds moves the table and the
-- headline together and the document keeps agreeing with itself while
-- describing a run that no longer happens. So the numbers live here, outside the
-- document, and two gates hold the three copies against each other:
--
--   test/spec/precision_golden_spec.lua  the document against this file. Runs
--                                         everywhere: no corpus, no network.
--   make precision                        a fresh run of the analyzer against
--                                         this file AND the document.
--
-- Field by field, and where each one comes from:
--
--   total          the sum of the codes below. Also the document's headline, and
--                  the spec checks that they are the same number rather than two
--                  numbers that happen to be close.
--   corpus_files   the .lua files under corpus/, which is the denominator the
--                  document quotes and the number `make corpus` prints. It is
--                  measured from the tree, so a corpus that has drifted under the
--                  document is a failure rather than a sentence nobody re-reads.
--   scanned_files  the files luasec itself selected (luasec.cli.walk). NOT the
--                  same number, and the difference is not noise: the walk reads
--                  cgi-bin handlers and the extensionless scripts beside them,
--                  which are Lua and are not named *.lua, and it declines four
--                  docsrc files called CHANGELOG.lua and README.lua, which are
--                  *.lua and are skipped on their name. Both numbers are frozen
--                  because both are claims a reader will quote, and only the
--                  second one is the analyzer's denominator.
--   codes          code -> findings for every code the run reported, plus 747 at
--                  zero. A code measured at zero is an assertion that the rule
--                  stays quiet on this corpus - the document spends a section on
--                  747 finding nothing and why that is not a precision figure -
--                  so it is recorded here rather than omitted, and a 747 finding
--                  is a failure like any other difference.
--
-- Measured with the command the document quotes, which is also what make
-- precision runs:
--
--   bin/luasec --std +openwrt+luci+luajit --format json -o /tmp/corpus.json corpus
--
-- To re-measure after changing a rule: run `make corpus && make precision`, then
-- update this file and docs/precision.md in the same commit. The gate is built so
-- that updating one without the other fails, which is the whole point of it.

return {
   corpus_files = 562,
   scanned_files = 566,
   total = 146,
   codes = {
      [701] = 3,
      [702] = 4,
      [703] = 6,
      [704] = 1,
      [705] = 5,
      [707] = 9,
      [708] = 36,
      [709] = 3,
      [724] = 27,
      [725] = 1,
      [727] = 12,
      [741] = 5,
      [747] = 0,
      [901] = 14,
      [903] = 20,
   },
}
