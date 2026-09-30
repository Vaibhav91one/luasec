local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true, assert_nil =
   harness.assert_equal, harness.assert_match, harness.assert_true, harness.assert_nil

local TAINTED = "test/fixtures/tainted_exec/handler.lua"

local function read(path)
   local handle = io.open(path, "rb")
   if not handle then return nil end
   local text = handle:read("*a")
   handle:close()
   return text
end

local function shim_dir(scripts)
   local dir = harness.scratch_dir("handoff")
   for name, body in pairs(scripts) do
      local handle = assert(io.open(dir .. "/" .. name, "wb"))
      handle:write(body)
      handle:close()
      os.execute(("chmod +x %q"):format(dir .. "/" .. name))
   end
   -- bin/luasec and the shims need dirname and cat, so link the system's
   -- copies in: PATH stays restricted to this dir, with no clipboard tool.
   for _, tool in ipairs({"dirname", "cat"}) do
      local pipe = io.popen("command -v " .. tool .. " 2>/dev/null")
      local path = pipe and pipe:read("*l")
      if pipe then pipe:close() end
      if path and path ~= "" then
         os.execute(("ln -sf %q %q"):format(path, dir .. "/" .. tool))
      end
   end
   return dir
end

local function agent_shim()
   return '#!/bin/sh\nd=$(dirname "$0")\necho invoked >> "$d/log"\nprintf "%s\\n" "$@" > "$d/args.txt"\n'
end

describe("handoff base64", function()
   it("encodes the RFC 4648 vectors exactly", function()
      local handoff = require "luasec.cli.handoff"
      assert_equal(handoff.osc52(""), "\27]52;c;\7", "empty")
      assert_equal(handoff.osc52("f"), "\27]52;c;Zg==\7", "f")
      assert_equal(handoff.osc52("fo"), "\27]52;c;Zm8=\7", "fo")
      assert_equal(handoff.osc52("foo"), "\27]52;c;Zm9v\7", "foo")
      assert_equal(handoff.osc52("foobar"), "\27]52;c;Zm9vYmFy\7", "foobar")
   end)
end)

describe("the agent hand-off submenu", function()
   it("shows the prompt and launches nothing", function()
      local dir = shim_dir({claude = agent_shim()})
      local out, code = harness.cli({"--interactive", TAINTED},
         {stdin = "fwqq", env = "PATH=" .. string.format("%q", dir)})
      local log = read(dir .. "/log")
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 1, "the exit code is the scan's: " .. out)
      assert_match(out, "Hand these findings to an agent", out)
      assert_match(out, "You are fixing security findings that luasec", out)
      assert_nil(log, "no agent was launched")
   end)

   it("answering n prints the prompt and launches nothing, approvals stay on", function()
      local dir = shim_dir({claude = agent_shim()})
      local out, code = harness.cli({"--interactive", TAINTED},
         {stdin = "fcn\nqq", env = "PATH=" .. string.format("%q", dir)})
      local log = read(dir .. "/log")
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 1, "the exit code is the scan's: " .. out)
      assert_match(out, "approval prompts ON", out)
      assert_match(out, "Launch claude%? %[y/N%]", out)
      assert_match(out, "You are fixing security findings that luasec", out)
      assert_nil(log, "answering n launches nothing")
   end)

   it("answering y launches the agent once with the approval-skip flag absent", function()
      local dir = shim_dir({claude = agent_shim()})
      local out, code = harness.cli({"--interactive", TAINTED},
         {stdin = "fcy\nqq", env = "PATH=" .. string.format("%q", dir)})
      local log = read(dir .. "/log")
      local args = read(dir .. "/args.txt")
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 1, "the exit code is the scan's: " .. out)
      assert_equal(log, "invoked\n", "the agent runs exactly once")
      assert_true(args:find("dangerously", 1, true) == nil, "no approval skip: " .. tostring(args))
      assert_match(tostring(args), "luasec reported 709", "the prompt is the argument: " .. out)
   end)

   it("copies through pbcopy when it is on PATH", function()
      local dir = shim_dir({
         claude = agent_shim(),
         pbcopy = '#!/bin/sh\nd=$(dirname "$0")\ncat > "$d/got.txt"\n',
      })
      local out, code = harness.cli({"--interactive", TAINTED},
         {stdin = "fyqq", env = "PATH=" .. string.format("%q", dir)})
      local got = read(dir .. "/got.txt")
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 1, "the exit code is the scan's: " .. out)
      assert_match(out, "copied with pbcopy", out)
      local fix = require "luasec.cli.fix_cmd"
      -- The menu hands its own argv down, so the re-run line keeps --interactive.
      local prompt = assert(fix.prompt_for({"--interactive", TAINTED}, "."))
      assert_equal(got, prompt, "the clipboard gets the prompt byte-identically")
   end)

   it("falls back to OSC 52 with no clipboard tool on PATH", function()
      local dir = shim_dir({})
      local out, code = harness.cli({"--interactive", TAINTED},
         {stdin = "fyqq", env = "PATH=" .. string.format("%q", dir)})
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 1, "the exit code is the scan's: " .. out)
      assert_match(out, "Copy prompt %(Recommended%)", "Copy prompt is recommended: " .. out)
      assert_match(out, "%]52;c;", "the OSC 52 sequence is written: " .. out)
      assert_match(out, "copied with the terminal %(OSC 52%)", out)
   end)
   it("flags only the agents that are missing as not installed", function()
      local dir = shim_dir({claude = agent_shim()})
      local out = harness.cli({"--interactive", TAINTED},
         {stdin = "fbqq", env = "PATH=" .. string.format("%q", dir)})
      os.execute("rm -rf " .. string.format("%q", dir))
      local claude = out:match("Claude Code[^\n]*")
      local codex = out:match("Codex[^\n]*")
      assert_true(claude ~= nil and codex ~= nil, out)
      assert_true(not claude:find("not installed", 1, true), "claude is on PATH: " .. claude)
      assert_match(claude, "%(Recommended%)", claude)
      assert_match(codex, "not installed", codex)
   end)
end)
