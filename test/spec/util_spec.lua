local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true, assert_false, assert_equal = harness.assert_true, harness.assert_false, harness.assert_equal

local util = require "luadoctor.util.util"

describe("wildcard API matching", function()
   it("matches an exact path", function()
      assert_true(util.wild_match("os.execute", "os.execute"))
      assert_false(util.wild_match("os.exec", "os.execute"))
   end)

   it("matches a star against any run of characters, including none", function()
      assert_true(util.wild_match("ffi.*", "ffi.load"))
      assert_true(util.wild_match("ffi.*", "ffi."))
      assert_true(util.wild_match("nixio.process.*", "nixio.process.execute"))
      assert_false(util.wild_match("ffi.*", "os.execute"))
   end)

   it("matches a question mark against exactly one character", function()
      assert_true(util.wild_match("os.exec?", "os.exec4"))
      assert_true(util.wild_match("os.exec?", "os.execs"))
      assert_false(util.wild_match("os.exec?", "os.exec"))
   end)

   it("does not treat dots as regular expression metacharacters", function()
      assert_false(util.wild_match("os.execute", "osXexecute"))
   end)

   it("rejects a subject shorter than the pattern", function()
      assert_false(util.wild_match("os.execute", "os.exec"))
   end)
end)

describe("entropy and encoding detection", function()
   it("reports low entropy for repetitive text and high for random-looking bytes", function()
      assert_true(util.entropy(string.rep("a", 64)) < 1)
      assert_true(util.entropy("Zm9vYmFyYmF6cXV1eGZvb2JhcmJhemZvb2Jhcg==") > 4)
   end)

   it("recognizes base64 and hex blobs by shape", function()
      assert_true(util.is_bas64("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"))
      assert_false(util.is_bas64("not base64 at all!!"))
      assert_true(util.is_hex_blob("deadbeefcafebabe0123456789abcdef"))
      assert_false(util.is_hex_blob("deadbeefzz"))
   end)
end)
