local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true, assert_no_match =
   harness.assert_equal, harness.assert_match, harness.assert_true, harness.assert_no_match

local TAINTED = "test/fixtures/tainted_exec/handler.lua"

local function q(text) return string.format("%q", text) end

-- Run luasec with `keys` on stdin (a pipe, so the menu only runs because of
-- --interactive), from `cwd`, and return combined output and the exit code.
local function drive(keys, args, cwd)
   local root = io.popen("pwd"):read("*l")
   local script = harness.scratch_dir("review_keys") .. "/keys"
   local handle = assert(io.open(script, "wb"))
   handle:write(keys)
   handle:close()
   local command = ("cd %s && %s %s < %s 2>&1; printf '\\n__EXIT__%%d' $?"):format(
      q(cwd or root), q(root .. "/bin/luasec"), args, q(script))
   local pipe = assert(io.popen(command))
   local out = pipe:read("*a")
   pipe:close()
   os.execute("rm -rf " .. q(script:match("^(.*)/keys$")))
   local code = tonumber(out:match("__EXIT__(%d+)%s*$"))
   return (out:gsub("\n?__EXIT__%d+%s*$", "")), code
end

-- A file with two exec findings on lines 1 and 2, so the browser has a
-- first finding and a second one to move to.
local function two_findings(dir)
   local handle = assert(io.open(dir .. "/a.lua", "wb"))
   handle:write("os.execute(arg[1])\nload(arg[2])\n")
   handle:close()
   return dir .. "/a.lua"
end

describe("the findings browser model", function()
   it("groups by category in order with counts, worst first, headers not in cursors", function()
      local review = require "luasec.cli.review"
      local list = {
         {code = "901", severity = "low", confidence = "low", file = "z.lua", line = 9, column = 1, message = "meta one"},
         {code = "721", severity = "high", confidence = "low", file = "b.lua", line = 2, column = 1, message = "firmware one"},
         {code = "701", severity = "high", confidence = "low", file = "b.lua", line = 2, column = 1, message = "exec high"},
         {code = "709", severity = "critical", confidence = "high", file = "a.lua", line = 1, column = 1, message = "exec critical"},
         {code = "747", severity = "high", confidence = "low", file = "c.lua", line = 1, column = 1, message = "payload one"},
      }
      local model = review.model(list)
      local kinds = {}
      for _, row in ipairs(model.rows) do kinds[#kinds + 1] = row.kind end
      assert_equal(kinds[1], "header", "first row is a header")
      assert_equal(model.rows[1].count, 2, "exec header counts its findings")
      -- Categories in categories.order(): exec, firmware, payload, artifact, meta.
      local seen = {}
      for _, row in ipairs(model.rows) do
         if row.kind == "header" then seen[#seen + 1] = row.label end
      end
      assert_true(#seen >= 4, "one header per non-empty category")
      local first_finding = model.rows[model.cursors[1]].finding
      assert_equal(first_finding.code, "709", "worst first inside exec")
      local second_finding = model.rows[model.cursors[2]].finding
      assert_equal(second_finding.code, "701", "high after critical")
      for _, index in ipairs(model.cursors) do
         assert_equal(model.rows[index].kind, "finding", "headers are not selectable")
      end
      assert_equal(#model.cursors, 5, "one cursor per finding")
   end)
end)

describe("the findings browser detail", function()
   it("shows the title, the code frame with the > marker, the fix and the refs", function()
      local review = require "luasec.cli.review"
      local api = require "luasec.api"
      local root = io.popen("pwd"):read("*l")
      local report = api.analyze({TAINTED}, {})
      assert_true(#report >= 1, "the fixture reports")
      local text = table.concat(review.detail(report[1], root), "\n")
      assert_match(text, "709  ", text)
      assert_match(text, TAINTED:gsub("%p", "%%%0") .. ":3", text)
      assert_match(text, "\n  > 3 | ", text)
      assert_match(text, "Do not build a shell command from request data", text)
      assert_match(text, "docs/rules/709%.md", text)
   end)

   it("shows a traced flow as source arrow sink lines", function()
      local review = require "luasec.cli.review"
      local api = require "luasec.api"
      local root = io.popen("pwd"):read("*l")
      local report = api.analyze({TAINTED}, {})
      local text = table.concat(review.detail(report[1], root), "\n")
      assert_match(text, "Why", text)
      assert_match(text, "http%.formvalue.*→.*os%.execute", text)
   end)
end)

describe("the findings browser run", function()
   it("moves over findings, shows the detail full-screen, and quits cleanly", function()
      local dir = harness.scratch_dir("review_run")
      local root = io.popen("pwd"):read("*l")
      local target = two_findings(dir)
      -- r enters review, j j moves, Enter shows full detail, q leaves it,
      -- q leaves the browser, q quits the menu.
      local out, code = drive("rjj\rqqq", "--interactive " .. q(target))
      os.execute("rm -rf " .. q(dir))
      assert_equal(code, 1, "the exit code is the scan's: " .. out)
      assert_match(out, "execution and dynamic code", "the browser groups by category: " .. out)
      assert_match(out, "> 701", "the cursor marks the first finding: " .. out)
      assert_match(out, "a%.lua:1", out)
      assert_match(out, "a%.lua:2", "the second finding's title is shown: " .. out)
      _ = root
   end)

   it("returns without hanging when stdin is closed inside the browser", function()
      local dir = harness.scratch_dir("review_eof")
      local target = two_findings(dir)
      local out, code = drive("r", "--interactive " .. q(target))
      os.execute("rm -rf " .. q(dir))
      assert_equal(code, 1, "EOF quits the browser and the menu: " .. out)
      assert_match(out, "execution and dynamic code", "the browser opened before EOF: " .. out)
   end)

   it("clamps the cursor at the last finding instead of running off the list", function()
      local dir = harness.scratch_dir("review_clamp")
      local target = two_findings(dir)
      local out, code = drive("rjjjjqq", "--interactive " .. q(target))
      os.execute("rm -rf " .. q(dir))
      assert_equal(code, 1, out)
      assert_match(out, "execution and dynamic code", "the browser opened: " .. out)
      assert_match(out, "a%.lua:2", "still on the last finding: " .. out)
      assert_no_match(out, "stopped", "no error from running off the end: " .. out)
   end)

   it("restores the terminal and reports instead of raising when rendering fails", function()
      local review = require "luasec.cli.review"
      local saved_read, saved_popen = io.read, io.popen
      io.read = function() return "q" end
      local err_text = {}
      local err = {write = function(_, ...) err_text[#err_text + 1] = table.concat({...}) end}
      local bad = {write = function() error("boom") end, flush = function() end}
      local finding = {code = "701", severity = "high", confidence = "low",
         file = "x.lua", line = 1, column = 1, message = "m"}
      local ok, failure = pcall(review.run, {finding}, {root = ".", out = bad, err = err})
      io.read = saved_read
      _ = saved_popen
      assert_true(ok, "the browser never raises: " .. tostring(failure))
      assert_match(table.concat(err_text), "boom", "the failure is reported")
   end)
end)
