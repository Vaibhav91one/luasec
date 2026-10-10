-- The library must render a report exactly the way the command line does, so a
-- caller that drives `api.analyze` and `api.format` itself produces bytes a human
-- could not tell from `bin/lua-doctor --format <name>`. The CLI's `emit` appends one
-- trailing newline to whatever `render` produces; the library call returns the
-- rendered report and does not add that newline, so it is stripped here.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_nil, assert_match = harness.assert_equal, harness.assert_nil, harness.assert_match
local api = require "luadoctor.api"

-- A fixture that yields at least one finding: a file whose only line runs
-- untrusted data to a command-execution sink.
local FIXTURE = "test/fixtures/tainted_exec/handler.lua"

-- Run the CLI with the named format and drop the trailing newline that `emit`
-- adds, so the result is exactly what `render` (and therefore `api.format`)
-- returns. `emit` writes `output, "\n"`, so the CLI's real stdout is the rendered
-- report plus one newline; the test harness appends its own marker line, so any
-- trailing newlines left after stripping the marker are artifacts of the harness
-- rather than of emit. The renderers themselves never emit a trailing newline.
local function cli_render(name)
   local out, _code = harness.cli({"--format", name, FIXTURE})
   out = out:gsub("\n+$", "")
   return out
end

describe("api.format", function()
   it("renders plain the same as the command line", function()
      local report = api.analyze({FIXTURE}, {})
      assert_equal(api.format(report, "plain"), cli_render("plain"))
   end)

   it("renders json the same as the command line", function()
      local report = api.analyze({FIXTURE}, {})
      assert_equal(api.format(report, "json"), cli_render("json"))
   end)

   it("renders sarif the same as the command line", function()
      local report = api.analyze({FIXTURE}, {})
      assert_equal(api.format(report, "sarif"), cli_render("sarif"))
   end)

   it("renders html the same as the command line", function()
      local report = api.analyze({FIXTURE}, {})
      assert_equal(api.format(report, "html"), cli_render("html"))
   end)

   it("returns nil and a message naming the unknown format for 'xml'", function()
      local ok, message = api.format({}, "xml")
      assert_nil(ok, "api.format must return nil for an unknown format")
      assert_match(message, "unknown format", "the message must name the unknown format")
   end)

   it("returns nil and a message naming the unknown format for a misspelled name", function()
      local ok, message = api.format({}, "jsoon")
      assert_nil(ok, "api.format must return nil for a misspelled format")
      assert_match(message, "unknown format", "the message must name the unknown format")
   end)
end)
