-- What role a file has, read from where it sits.
--
-- One question, asked of a path: is this a file the analysed program SHIPS, or
-- is it part of the test suite that exercises it? 747 asks it, because a
-- credential-shaped literal means two different things in the two, and the
-- finding's severity is the statement about which of them this is.
--
--   a credential in code that ships is an exposure: it is in the image,
--     anyone who unzips the image can read it, and it is what CWE-798 is.
--   a credential-shaped literal in a test suite is a fixture. A parser's own
--     table of URLs has to carry a password with a `#` in it or the parser is
--     not being tested, so the most deliberately credential-shaped strings in a
--     project are its fixtures. Reporting one at `high` is the finding that
--     teaches a reader to skip `high`.
--
-- There is no way to read this off the file's contents - the two files are
-- the same program - so it is read off the path, which is the only evidence
-- there is. The vocabulary below is deliberately blunt: a segment named like a
-- test suite, or a file whose own name says it is one. Precision about intent
-- was the other route #290 offered, and it is the wrong one here - a table
-- that is "clearly a fixture" is how firmware writes an FTP connection
-- configuration, and nothing in the table says which of the two it is.
--
-- A path that is absent is NOT a test file. `check_source` hands the analyzer
-- a string with no file behind it, and the caller who did that is not a
-- caller who is looking at a fixture.
local M = {}

-- Directory names a test suite lives under, matched as whole segments.
--
-- There is no `t` here, and its absence is measured rather than stylistic. `t`
-- is the OpenResty and Test::Nginx convention, so it looks like it belongs; and
-- a whole-segment match on it demotes every finding in every temporary file on
-- macOS, where `$TMPDIR` is `/var/folders/<a>/<b>/T/` and the directory the
-- system hands you for scratch space is named `T`. A security rule cannot lower
-- severity on a directory name the operating system chose, and the corpus says
-- what the entry costs: the five `.lua` files under the OpenResty `t/`
-- directories are library helpers with no credential-shaped literal in any of
-- them, so on this corpus `t` buys nothing and hides a real credential class.
-- A project that wants it can say so in the source, with
-- `-- luasec: ignore 747`, which is a decision recorded where the file is.
local TEST_DIRECTORIES = {
   test = true, tests = true,
   spec = true, specs = true,
}

-- A file whose own name says it is a test. Matched on the stem, so
-- `telnet_login_test.lua`, `test_telnet_login.lua` and `telnet_login_spec.lua`
-- are all the same claim whatever they are called.
local TEST_STEM_PREFIXES = {"test", "spec"}
local TEST_STEM_SUFFIXES = {"_test", "_tests", "_spec", "_specs"}

-- The last path segment, with its directory part dropped and its extension
-- taken off. Scanned by hand rather than with `([^/]+)$`, which backtracks on
-- a long path.
local function stem_of(path)
   local cut = 1
   for index = 1, #path do
      local char = path:sub(index, index)
      -- A backslash is a separator as well: a path can arrive from a caller on
      -- Windows, and `dir\test\x.lua` is the same tree as `dir/test/x.lua`.
      if char == "/" or char == "\\" then cut = index + 1 end
   end
   local name = path:sub(cut)
   -- `.rockspec` and `.luac` keep their dot; only the LAST extension goes.
   local stop = name:find("%.[^.]+$")
   if stop and stop > 1 then name = name:sub(1, stop - 1) end
   return name:lower()
end

-- Does any directory segment of `path` name a test suite?
--
-- Whole segments only. `contest` and `latest` contain `test` and neither is a
-- test suite, and a substring match would take both - and `spec` inside
-- `spectrum`, which is how a graphics library names a module.
local function in_a_test_directory(path)
   local segment_start = 1
   for index = 1, #path do
      local char = path:sub(index, index)
      if char == "/" or char == "\\" then
         if TEST_DIRECTORIES[path:sub(segment_start, index - 1):lower()] then return true end
         segment_start = index + 1
      end
   end
   return TEST_DIRECTORIES[path:sub(segment_start):lower()] == true
end

-- Does the file's own name say it is a test?
local function named_as_a_test(path)
   local stem = stem_of(path)
   if stem == "" then return false end
   for _, prefix in ipairs(TEST_STEM_PREFIXES) do
      -- `test` and nothing else, or `test_` and something: `testing` is a
      -- framework's module, not a test file's name.
      if stem == prefix then return true end
      if stem:sub(1, #prefix + 1) == prefix .. "_" then return true end
   end
   for _, suffix in ipairs(TEST_STEM_SUFFIXES) do
      if #stem > #suffix and stem:sub(-#suffix) == suffix then return true end
   end
   return false
end

--- Is `path` part of a test suite rather than a program that ships?
--
-- False for nil, for an empty path and for anything that is not a string: an
-- answer of `true` here lowers a finding, and a caller that passes something
-- this cannot read has not said the file is a test.
function M.is_test(path)
   if type(path) ~= "string" or path == "" then return false end
   return in_a_test_directory(path) or named_as_a_test(path)
end

return M