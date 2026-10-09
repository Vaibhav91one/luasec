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
-- and every number in that change was larger than the one before it. The growth
-- was new measurement surface and nothing else, and the split was taken before
-- those figures were written. Over the four entries that were already here the
-- run was identical to main's, finding for finding - the multiset of (code,
-- file, line, column, message) over `luci`, `luci-1806`, `openwrt-packages` and
-- `luajit` was equal before and after - and every code that was reported before
-- was reported the same number of times. All of that increase was in the six new
-- directories, and #288 below is the first thing to have moved this table down.
--
-- What the new directories are, and what they are not, is in docs/precision.md.
-- The short form: they buy FFI false-positive surface and crypto/encoding
-- surface, not request-handler flow. They contribute nothing at all to 704, 708,
-- 709, 710, 712 or 724, and the reason is the one #262 predicted - these are
-- libraries, and a library is not a request handler. Reading them as though they
-- measured handler flow would be the easy mistake to make here.
--
-- The walker stopped claiming files that are not Lua are Lua, and with it 525
-- findings went away. #288 is the first change in this table's history where the
-- headline moved DOWN by more than a single finding, and the whole 525 is
-- accounted for in docs/precision.md - which is the only place that can say
-- whether each one was noise or a real detection inside a file that had no
-- business being read. In short: 436 of them were 901/902/903 on files that are
-- not Lua, which is 94% of every parse failure this corpus produces, and the
-- other 89 were real findings inside the Lua that Test::Nginx specs carry in
-- heredocs, which is a coverage loss this change caused and has filed.
--
-- Over the four entries that were already here the run is unchanged, finding for
-- finding and code for code: 248, and 701=49, 708=22, 709=23, 901=10, 903=20 both
-- before and after. Those four carry no `.t` file and no `.git`, which is why
-- they are the control.
--
-- The four figures that are NOT 691 and NOT the total are worth stating once:
--
--   scanned_files fell 964 -> 706, and corpus_files did not move at all. 691 is
--      `find corpus -name '*.lua'`, which never counted a `.t` spec or a
--      packed-refs, so it is the same number it always was. The 258 files the
--      walk gave up are 250 Test::Nginx specs, 2 `.git/packed-refs`, a
--      `tapset/ngx_lua.stp` probe, `util/gen-lexer-c`, `makefile.dist`,
--      `ci`, `ci-coverage` and `luasocket/test/cgi/cat`. Not one of them was a
--      `.lua` file: the walk selected 687 `.lua` files before this change and
--      selects the same 687 after, and that is the direction this fix is not
--      allowed to move.
return {
   corpus_files = 691,
   scanned_files = 706,
   total = 610,
   codes = {
      [701] = 46,
      [702] = 14,
      [703] = 20,
      [704] = 21,
      [705] = 22,
      [707] = 346,
      [708] = 21,
      [709] = 27,
      [710] = 1,
      -- Zero, and recorded for the same reason 741 and 747 are: a code measured
      -- at zero is an assertion that the rule stays quiet here. 711 was six
      -- backtick command literals, all six inside `.t` specs; 902 was six
      -- unsupported-dialect reports, all six on the same specs.
      [711] = 0,
      [712] = 3,
      [724] = 25,
      [725] = 2,
      [727] = 16,
      [728] = 1,
      [741] = 0,
      [747] = 15,
      [901] = 10,
      [902] = 0,
      [903] = 20,
   },
}
