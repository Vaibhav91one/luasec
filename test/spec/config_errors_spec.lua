-- A bad configuration has two shapes in this module, and which one a caller gets
-- must not depend on which function they happened to call:
--
--   api.validate_options  returns nil plus a message
--   the entry points      raise the {luasec_config_error = true} object
--
-- A Lua traceback is neither of those. It is what `profiles.split` raised when
-- `std` arrived as a table, and a library caller cannot tell a typo in its own
-- config from a crash in the analyzer. These tests are about the shape, so they
-- go through pcall and reject a traceback explicitly rather than matching text.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_false, assert_nil =
   harness.assert_equal, harness.assert_true, harness.assert_false, harness.assert_nil
local assert_match = harness.assert_match

local api = require "luasec.api"

-- The options table `api` is handed, refused the way a library caller refuses it:
-- no raising, a message, and nothing installed. `validate_options` and
-- `rules_load` both have this signature.
local function refused_by(fn, ...)
   local ok, accepted, message = pcall(fn, ...)
   assert_true(ok, "expected a nil-and-message refusal, got a raised error: " .. tostring(accepted))
   assert_nil(accepted, "a refused configuration must not be accepted")
   assert_equal(type(message), "string", "a refusal must carry a message")
   return message
end

-- The same refusal at an entry point, which cannot return nil in place of a
-- findings array without changing its own signature, so it raises the object the
-- module already raises for an unloadable profile.
local function rejected_by_entry(fn, ...)
   local ok, err = pcall(fn, ...)
   assert_false(ok, "expected a configuration error, got a clean return")
   assert_equal(type(err), "table",
      "expected the config-error object, got a Lua traceback: " .. tostring(err))
   assert_true(err.luasec_config_error, "the raised error must be marked as a config error")
   assert_equal(type(err.message), "string", "the raised error must carry a message")
   return err.message
end

describe("configuration errors", function()
   it("refuses a std given as a table rather than raising out of the library", function()
      local message = refused_by(api.validate_options, {std = {"openwrt"}})
      assert_match(message, "%-%-std")
   end)

   it("refuses a std given as a table at check_source too", function()
      local message = rejected_by_entry(api.check_source, "return 1", {std = {"openwrt"}})
      assert_match(message, "%-%-std")
   end)

   it("refuses a std given as a table at analyze too", function()
      local message = rejected_by_entry(api.analyze, {"test/fixtures/clean/report.lua"},
         {std = {"openwrt"}})
      assert_match(message, "%-%-std")
   end)

   -- Every list option is read with ipairs, and ipairs over a string runs zero
   -- times, so these were accepted and then ignored: a --rules file that was
   -- never loaded and a --only that selected nothing both came back as a clean
   -- run of the analysis the caller did not ask for.
   it("refuses a rules option given as a bare string instead of loading no profile", function()
      local message = refused_by(api.validate_options, {rules = "vendor.lua"})
      assert_match(message, "%-%-rules")
   end)

   it("refuses a rules entry that is not a file path", function()
      local message = refused_by(api.validate_options, {rules = {true}})
      assert_match(message, "%-%-rules")
      assert_match(message, "boolean")
   end)

   it("refuses a filter pattern that is not a string", function()
      local message = refused_by(api.validate_options, {only = {701}})
      assert_match(message, "%-%-only")
   end)

   it("refuses an ignore list given as a bare string instead of ignoring nothing", function()
      local message = refused_by(api.validate_options, {ignore = "709"})
      assert_match(message, "%-%-ignore")
   end)

   it("names the option that was wrong rather than the first one it checked", function()
      local message = refused_by(api.validate_options,
         {only = {"709"}, ignore = {"012"}, enable = {false}})
      assert_match(message, "%-%-enable")
   end)

   it("refuses a source API path that is not a string", function()
      local message = refused_by(api.validate_options, {sources = {42}})
      assert_match(message, "sources")
   end)

   it("refuses a sanitizer name that is not a string", function()
      local message = refused_by(api.validate_options, {sanitizers = {42}})
      assert_match(message, "sanitizers")
   end)

   it("refuses an options table that is not a table", function()
      local message = refused_by(api.validate_options, "std=openwrt")
      assert_match(message, "table")
   end)

   it("still accepts a configuration that is entirely well formed", function()
      local ok, message = api.validate_options({
         std = "+openwrt+luci",
         rules = {"src/luasec/registry/stds/openwrt.lua"},
         only = {"709", "rce"},
         ignore = {"012"},
         sources = {"uci.get"},
         sanitizers = {"luci.util.shellquote"},
      })
      assert_true(ok, "a valid configuration was refused: " .. tostring(message))
   end)

   -- The CLI checks its own numbers in main.lua, so these reached the analysis
   -- only from a library caller, and they are arithmetic: `max_nodes + 1` on the
   -- string "abc" raised out of the parser, and max_function_lines was compared
   -- against a line count.
   it("refuses a max-nodes that is not a number before anything adds to it", function()
      local message = refused_by(api.validate_options, {max_nodes = "abc"})
      assert_match(message, "%-%-max%-nodes")
   end)

   it("refuses a non-numeric max-nodes at check_source too", function()
      local message = rejected_by_entry(api.check_source, "return 1", {max_nodes = "abc"})
      assert_match(message, "%-%-max%-nodes")
   end)

   it("refuses a max-nodes that is not a positive integer", function()
      assert_match(refused_by(api.validate_options, {max_nodes = 0}), "%-%-max%-nodes")
      assert_match(refused_by(api.validate_options, {max_nodes = -1}), "%-%-max%-nodes")
      assert_match(refused_by(api.validate_options, {max_nodes = 1.5}), "%-%-max%-nodes")
   end)

   it("refuses a max_function_lines that is not a number", function()
      local message = refused_by(api.validate_options, {max_function_lines = "x"})
      assert_match(message, "max_function_lines")
   end)

   it("refuses a jobs that is not a number, the way the CLI already does", function()
      local message = refused_by(api.validate_options, {jobs = "abc"})
      assert_match(message, "%-%-jobs")
   end)

   it("refuses a source_confidence that is not a string", function()
      local message = refused_by(api.validate_options,
         {sources = {"uci.get"}, source_confidence = 42})
      assert_match(message, "source_confidence")
   end)

   -- The CLI's own parser stores every numeric flag as the string it was given,
   -- and hands that straight to api, so a string the CLI produced is not a
   -- config error: refusing it would break every --max-nodes run.
   it("accepts the number the CLI's own parser hands down as a string", function()
      local ok, message = api.validate_options({max_nodes = "20000", jobs = "2"})
      assert_true(ok, "the CLI's own numeric flags were refused: " .. tostring(message))
   end)

   -- The first argument is used as a string on the next line of the analyzer: the
   -- decoder, io.open. None of it was checked, and the two ways it went wrong are
   -- both worse than a traceback. A number became a 901 "source could not be
   -- parsed", which is a security result about the caller's own argument, and
   -- `analyze("one/file.lua")` ran ipairs over a string, which yields nothing at
   -- all and returned an empty report: a clean run of no analysis whatsoever.
   it("refuses a source that is not a string rather than letting the decoder fail on it", function()
      assert_match(rejected_by_entry(api.check_source, nil), "source")
      assert_match(rejected_by_entry(api.check_source, {}), "source")
      assert_match(rejected_by_entry(api.check_source, true), "source")
   end)

   it("refuses a number given as the source instead of reporting it as unparseable", function()
      local message = rejected_by_entry(api.check_source, 42)
      assert_match(message, "source")
      assert_match(message, "number")
   end)

   it("refuses a single path given to analyze instead of reporting a clean run of nothing", function()
      local message = rejected_by_entry(api.analyze, "test/fixtures/clean/report.lua")
      assert_match(message, "paths")
      assert_match(message, "string")
   end)

   it("refuses paths that is not a list", function()
      local message = rejected_by_entry(api.analyze, 42)
      assert_match(message, "paths")
   end)

   it("refuses a path entry that is not a string", function()
      local message = rejected_by_entry(api.analyze, {42})
      assert_match(message, "path")
   end)

   it("refuses a rules_load argument that is not a list of files", function()
      local message = refused_by(api.rules_load, "vendor.lua")
      assert_match(message, "rules")
   end)

   -- The over-reach this could cause: a path that does not exist is a finding
   -- about the file, not a mistake in the caller's arguments, and has to stay
   -- one. It is the only way this tool reports a file it could not read.
   it("still reports a file it cannot read as a finding rather than a config error", function()
      local report = api.analyze({"test/fixtures/does_not_exist.lua"})
      assert_equal(#report, 1, "the unreadable file must be reported")
      assert_equal(report[1].code, "901")
      assert_match(report[1].message, "cannot read file")
   end)
end)
