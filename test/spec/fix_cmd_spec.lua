local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_true

local TAINTED = "test/fixtures/tainted_exec/handler.lua"

-- Run the CLI with a PATH that starts with `dir`, so a stub agent there is the
-- one launched.
local function run_with_path(dir, args)
   local cmd = ("PATH=%q:\"$PATH\" ./bin/luasec"):format(dir)
   for _, a in ipairs(args) do cmd = cmd .. " " .. string.format("%q", a) end
   local pipe = assert(io.popen(cmd .. " 2>&1; printf '\\n__EXIT__%d' $?"))
   local out = pipe:read("*a")
   pipe:close()
   local code = tonumber(out:match("__EXIT__(%d+)%s*$"))
   return out:gsub("\n?__EXIT__%d+%s*$", ""), code
end

local function stub_agent(dir, name)
   local path = dir .. "/" .. name
   local handle = assert(io.open(path, "w"))
   handle:write('#!/bin/sh\nprintf "%s\\n" "$@" > "$(dirname "$0")/args.txt"\n')
   handle:close()
   os.execute(("chmod +x %q"):format(path))
end

local function read(path)
   local handle = io.open(path, "rb")
   if not handle then return nil end
   local text = handle:read("*a")
   handle:close()
   return text
end

describe("luasec fix", function()
   it("prints a prompt with the untrusted-code warning and each finding's fix prompt", function()
      local out, code = harness.cli({"fix", "--print", TAINTED})
      assert_equal(code, 0, out)
      assert_match(out, "may be hostile firmware", out)
      assert_match(out, "%[709%] critical", out)
      assert_match(out, "luasec reported 709 %(untrusted data reaches command execution%) at "
         .. TAINTED:gsub("%p", "%%%0") .. ":3%.", out)
      assert_true(not out:find("{file}", 1, true), "placeholders are filled in")
   end)

   it("launches claude with approvals skipped by default, and says so", function()
      local dir = harness.scratch_dir("fix_claude")
      stub_agent(dir, "claude")
      local out, code = run_with_path(dir, {"fix", TAINTED})
      local args = read(dir .. "/args.txt")
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 0, out)
      assert_match(out, "approvals skipped", out)
      assert_match(args, "^%-%-dangerously%-skip%-permissions\n", args)
      assert_match(args, "luasec reported 709", args)
   end)

   it("keeps approvals on with --safe", function()
      local dir = harness.scratch_dir("fix_safe")
      stub_agent(dir, "codex")
      local out, code = run_with_path(dir, {"fix", "--agent", "codex", "--safe", TAINTED})
      local args = read(dir .. "/args.txt")
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 0, out)
      assert_true(not out:find("approvals skipped", 1, true), out)
      assert_true(not args:find("dangerously", 1, true), args)
   end)

   it("launches nothing when there is nothing to fix", function()
      local out, code = harness.cli({"fix", "test/fixtures/clean/report.lua"})
      assert_equal(code, 0, out)
      assert_match(out, "nothing to fix", out)
   end)

   it("refuses an unknown agent, and a missing one", function()
      local out, code = harness.cli({"fix", "--agent", "copilot", TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "claude, codex, cursor", out)
      -- Only the system directories: prepending to the real PATH would find,
      -- and launch, a cursor-agent installed on the machine running the specs.
      local pipe = assert(io.popen("PATH=/usr/bin:/bin ./bin/luasec fix --agent cursor "
         .. string.format("%q", TAINTED) .. " 2>&1; printf '\\n__EXIT__%d' $?"))
      out = pipe:read("*a")
      pipe:close()
      assert_match(out, "__EXIT__2%s*$", out)
      assert_match(out, "cursor%-agent is not on PATH", out)
   end)

   it("selects findings the way the scan does", function()
      local out, code = harness.cli({"fix", "--print", "--ignore", "709", TAINTED})
      assert_equal(code, 0, out)
      assert_match(out, "nothing to fix", out)
   end)

   it("exposes the --print prompt byte-identically through prompt_for", function()
      local fix = require "luasec.cli.fix_cmd"
      local out, code = harness.cli({"fix", "--print", TAINTED})
      assert_equal(code, 0, out)
      local prompt, message = fix.prompt_for({TAINTED}, ".")
      assert_true(prompt ~= nil, "a prompt is returned: " .. tostring(message))
      -- harness.cli leaves the printf's own newline on the output, so strip
      -- exactly that one before the byte-identical comparison.
      assert_equal(out:gsub("\n$", ""), prompt .. "\n", "prompt_for shares the --print path")
      local empty, why = fix.prompt_for({"test/fixtures/clean/report.lua"}, ".")
      assert_equal(empty, nil, "nothing to fix is nil")
      assert_equal(why, "nothing to fix", "with the reason")
   end)
end)
