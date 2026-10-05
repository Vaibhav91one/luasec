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

-- The corpus grew in #262: six OpenResty entries joined the four firmware ones,
-- so every number here is larger than it was. The growth is new measurement
-- surface and nothing else, and the split was taken before these figures were
-- written. Over the four entries that were already here the run is identical to
-- main's, finding for finding - the multiset of (code, file, line, column,
-- message) over `luci`, `luci-1806`, `openwrt-packages` and `luajit` is equal
-- before and after - and every code that was reported before is reported the
-- same number of times. All of the increase is in the six new directories.
--
-- What the new directories are, and what they are not, is in docs/precision.md.
-- The short form: they buy FFI false-positive surface and crypto/encoding
-- surface, not request-handler flow. They contribute nothing at all to 704, 708,
-- 709, 710, 712 or 724, and the reason is the one #262 predicted - these are
-- libraries, and a library is not a request handler. Reading them as though they
-- measured handler flow would be the easy mistake to make here.
--
-- Three codes in this table (711, 728, 902) and a large share of 901 and 903 are
-- findings in files that are not Lua at all: the Test::Nginx `.t` spec files in
-- lua-resty-core and lua-nginx-module are Perl, and the walk reads them as Lua
-- because it has no `.t` in its not-Lua list and does descend into `.git/`. That
-- is a walker defect rather than a property of OpenResty, it is filed as #288,
-- and it is recorded here rather than engineered away: an earlier draft of this
-- change removed the `.git/packed-refs` findings by relocating the git
-- directories outside the corpus, which would have made the frozen table smaller
-- and the defect harder to find.
return {
   corpus_files = 691,
   scanned_files = 964,
   total = 1136,
   codes = {
      [701] = 67,
      [702] = 19,
      [703] = 25,
      [704] = 21,
      [705] = 23,
      [707] = 401,
      [708] = 22,
      [709] = 23,
      [710] = 1,
      [711] = 6,
      [712] = 3,
      [724] = 25,
      [725] = 2,
      [727] = 16,
      [728] = 1,
      [741] = 0,
      [747] = 15,
      [901] = 268,
      [902] = 6,
      [903] = 192,
   },
}
