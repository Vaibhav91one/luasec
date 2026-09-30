local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_true

local TAINTED = "test/fixtures/tainted_exec/handler.lua"

local function q(text) return string.format("%q", text) end

-- Run luasec with `keys` on stdin (a pipe, so the menu only runs because of
-- --interactive), from `cwd`, and return combined output and the exit code.
local function drive(keys, args, cwd)
   local root = io.popen("pwd"):read("*l")
   local script = harness.scratch_dir("menu_keys") .. "/keys"
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

describe("the interactive menu", function()
   it("is not shown in a pipe unless forced, and never changes the exit code", function()
      local out, code = drive("q", TAINTED)
      assert_equal(code, 1, out)
      assert_true(not out:find("What next?", 1, true), out)
      local forced, forced_code = drive("q", "--interactive " .. TAINTED)
      assert_equal(forced_code, 1, "the exit code is the scan's: " .. forced)
      assert_match(forced, "What next%?\n> r  review findings\n", forced)
      assert_match(forced, "\n  q  quit", forced)
   end)

   it("is off with --no-interactive, and with the other output modes", function()
      for _, extra in ipairs({"--no-interactive", "--summary", "--score", "--quiet", "--format json"}) do
         local out = drive("q", "--interactive " .. extra .. " " .. TAINTED)
         assert_true(not out:find("What next?", 1, true), extra .. ": " .. out)
      end
   end)

   it("explains a finding the way why does, without a second scan", function()
      local out = drive("e1\nq", "--interactive " .. TAINTED)
      assert_match(out, "Which finding%? %[1%-1%]: ", out)
      assert_match(out, "\n  > 3 | ", out)
      assert_match(out, "how to fix:", out)
   end)

   it("shows every finding, returns to the menu, and quits", function()
      local out = drive("aq", "--interactive " .. TAINTED)
      local _, shown = out:gsub("%[709%] critical:", "")
      assert_equal(shown, 2, "once in the report and once from `a`: " .. out)
      local _, menus = out:gsub("What next%?", "")
      assert_equal(menus, 2, "the menu comes back after an action: " .. out)
   end)

    it("moves the mark with the arrow keys and runs it on Enter", function()
       -- Down, Down, Down: the fourth item, `a  show every finding`.
       local out = drive("\27[B\27[B\27[B\rq", "--interactive " .. TAINTED)
      local _, shown = out:gsub("%[709%] critical:", "")
      assert_equal(shown, 2, out)
   end)

   it("saves a report only when asked, to the file named", function()
      local dir = harness.scratch_dir("menu_save")
      local out = drive("sjson\n" .. dir .. "/r.json\nq", "--interactive " .. TAINTED)
      local handle = io.open(dir .. "/r.json", "rb")
      local text = handle and handle:read("*a") or ""
      if handle then handle:close() end
      os.execute("rm -rf " .. q(dir))
      assert_match(out, "wrote " .. dir:gsub("%p", "%%%0") .. "/r%.json", out)
      assert_match(text, '"findings"', "a JSON report was written")
   end)

   it("writes a baseline the next run can use", function()
      local dir = harness.scratch_dir("menu_base")
      local out = drive("b" .. dir .. "/b.json\nq", "--interactive " .. TAINTED)
      local again, code = harness.cli({"--baseline", dir .. "/b.json", TAINTED})
      os.execute("rm -rf " .. q(dir))
      assert_match(out, "use luasec %-%-baseline", out)
      assert_equal(code, 0, "nothing is new against its own baseline: " .. again)
   end)

   it("prints the fix prompt by default and launches nothing", function()
      local out = drive("f\n\n\nq", "--interactive " .. TAINTED)
      assert_match(out, "Agent %[claude/codex/cursor%] %(claude%): ", out)
      assert_match(out, "You are fixing security findings that luasec", out)
      assert_true(not out:find("launching", 1, true), "nothing was launched: " .. out)
   end)

   it("sets up CI and installs guidance in the directory it runs from", function()
      local dir = harness.scratch_dir("menu_setup")
      local root = io.popen("pwd"):read("*l")
      drive("c\ni\nq", "--interactive " .. q(root .. "/" .. TAINTED), dir)
      local workflow = io.open(dir .. "/.github/workflows/luasec.yml", "rb")
      local skill = io.open(dir .. "/.claude/skills/luasec/SKILL.md", "rb")
      local made = {workflow ~= nil, skill ~= nil}
      if workflow then workflow:close() end
      if skill then skill:close() end
      os.execute("rm -rf " .. q(dir))
      assert_equal(made[1], true, "ci install wrote the workflow")
      assert_equal(made[2], true, "install wrote the skill")
   end)
   it("treats Ctrl-C as quit, so a terminal is restored rather than left in single-key mode", function()
      local out, code = drive("\3", "--interactive " .. TAINTED)
      assert_equal(code, 1, out)
      local _, menus = out:gsub("What next%?", "")
      assert_equal(menus, 1, "shown once, then quit: " .. out)
   end)
end)
