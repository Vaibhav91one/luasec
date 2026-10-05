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
-- `t` is here, and it is here because `t/` is how OpenResty and Test::Nginx
-- spell a test suite - a real layout, in wide use, and one this repository's
-- corpus happens to contain. #290 left it out on a measurement: the five `.lua`
-- files under the OpenResty `t/` directories in the corpus hold no
-- credential-shaped literal, so on this corpus the entry buys nothing. That is
-- corpus-fitting for a rule that ships to scan trees nobody here has cloned, and
-- it hid a credential class in every other OpenResty checkout.
--
-- The macOS scratch directory is a real bug and it is answered below, by
-- excluding temp roots rather than by deleting a class: what makes
-- `/var/folders/<a>/<b>/T/` dangerous is that the OPERATING SYSTEM named it,
-- not that it is one letter long.
local TEST_DIRECTORIES = {
   test = true, tests = true,
   spec = true, specs = true,
   t = true,
}

-- Absolute prefixes of the directories an operating system hands a process for
-- scratch space. Nothing under one of these is a test suite, however its
-- directories are named, and the answer is `false` for the WHOLE vocabulary -
-- `tests/` and `test_login_spec.lua` included - because a directory the system
-- picked is not a place a project's test suite was laid out.
--
-- macOS is the case this exists for: `$TMPDIR` there is
-- `/var/folders/<a>/<b>/T/`, so a whole-segment match on `t` would lower the
-- severity of every finding in every scratch file this tool is pointed at,
-- including a firmware image a CI job unpacked. `/private/` is listed beside
-- each root because `/var` and `/tmp` are symlinks to it on macOS and a
-- resolved path can be spelled either way.
local TEMP_ROOTS = {
   "/var/folders/", "/private/var/folders/",
   "/tmp/", "/private/tmp/",
}

-- The directory the process was started in, or nil when it cannot be read.
--
-- `$TMPDIR` is honoured separately below; this is about a RELATIVE path, which
-- has to be resolved against something before an absolute prefix can mean
-- anything. `PWD` is what the shell maintains and what `make` passes down, and
-- the `os.rename` is the guard against a stale one: renaming a directory onto
-- itself succeeds only when the directory is really there. Read once per
-- process, because it cannot change while the tool runs.
local working_directory
local function cwd()
   if working_directory ~= nil then return working_directory end
   working_directory = false
   local candidate = os.getenv("PWD")
   if type(candidate) == "string" and candidate:find("/", 1, true) == 1 then
      if os.rename(candidate, candidate) then working_directory = candidate end
   end
   return working_directory or nil
end

-- The path as one absolute, normalised string: separators unified, `.` and `..`
-- folded away, and a relative path joined onto the working directory.
--
-- The folding is not tidiness. `/tmp/../etc/t/x.lua` is a file in `/etc` and
-- has to be read as one, or a prefix match on `/tmp/` is something a caller
-- walks around by typing one `..`.
local function absolute(path)
   local unified = path:gsub("\\", "/")
   local was_absolute = unified:find("/", 1, true) == 1
   if not was_absolute then
      local base = cwd()
      if not base then return unified end
      unified = base .. "/" .. unified
   end
   local parts = {}
   for segment in unified:gmatch("[^/]+") do
      if segment == ".." then
         if #parts > 0 then table.remove(parts) end
      elseif segment ~= "." then
         parts[#parts + 1] = segment
      end
   end
   return (was_absolute and "/" or "") .. table.concat(parts, "/")
end

--- Is `path` under a temporary root the operating system chose?
--
-- Lower case throughout: the filesystem is case-insensitive on the platform
-- whose scratch directory this is, so `/TMP/x` and `/tmp/x` are one directory
-- and only one of them is spelled here.
local function in_a_temp_root(path)
   local resolved = absolute(path):lower()
   for _, root in ipairs(TEMP_ROOTS) do
      if resolved:sub(1, #root) == root then return true end
   end
   -- `$TMPDIR` when the caller set it, which is the one root this process
   -- cannot know in advance: `mktemp -d` honours it and nothing here can ask
   -- where the result went. It goes through the same resolution as the path,
   -- because a caller that sets it relative gets a relative directory back out
   -- of `mktemp` and would otherwise slip past an absolute prefix.
   -- Compared with a trailing separator, so a `$TMPDIR` of `/build` does not
   -- swallow `/builder/`.
   local tmpdir = os.getenv("TMPDIR")
   if type(tmpdir) == "string" and tmpdir ~= "" then
      local root = absolute(tmpdir):lower():gsub("/+$", "") .. "/"
      if resolved:sub(1, #root) == root then return true end
   end
   return false
end

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
--
-- A temporary root answers `false` before the vocabulary is consulted at all,
-- and it is the reason `t` can be in that vocabulary.
function M.is_test(path)
   if type(path) ~= "string" or path == "" then return false end
   if in_a_temp_root(path) then return false end
   return in_a_test_directory(path) or named_as_a_test(path)
end

return M