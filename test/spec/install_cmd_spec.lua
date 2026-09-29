local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_true

local function read(path)
   local handle = io.open(path, "rb")
   if not handle then return nil end
   local text = handle:read("*a")
   handle:close()
   return text
end

describe("luasec install", function()
   it("writes the Claude skill, the Cursor rule and an AGENTS.md block", function()
      local dir = harness.scratch_dir("install_all")
      local out, code = harness.cli({"install", "--dir", dir})
      assert_equal(code, 0, out)
      local skill = read(dir .. "/.claude/skills/luasec/SKILL.md")
      assert_true(skill, "skill written")
      assert_match(skill, "^%-%-%-\nname: luasec\ndescription: ", "skill front matter")
      assert_match(read(dir .. "/.cursor/rules/luasec.mdc"), "luasec rules explain", "cursor rule")
      assert_match(read(dir .. "/AGENTS.md"), "<!%-%- luasec:start %-%->", "agents block")
      assert_match(out, "wrote " .. dir:gsub("%p", "%%%0") .. "/AGENTS.md", out)
      os.execute("rm -rf " .. string.format("%q", dir))
   end)

   it("keeps the rest of AGENTS.md and replaces its own block on a second run", function()
      local dir = harness.scratch_dir("install_agents")
      local handle = assert(io.open(dir .. "/AGENTS.md", "w"))
      handle:write("# Project rules\n\nKeep this.\n")
      handle:close()
      harness.cli({"install", "--dir", dir, "agents"})
      local first = read(dir .. "/AGENTS.md")
      harness.cli({"install", "--dir", dir, "agents"})
      local second = read(dir .. "/AGENTS.md")
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_match(first, "^# Project rules\n\nKeep this.\n", "the project's text stays first")
      assert_equal(second, first, "a second run changes nothing")
      local _, blocks = first:gsub("luasec:start", "")
      assert_equal(blocks, 1, "one block, not two")
   end)

   it("writes only the named target", function()
      local dir = harness.scratch_dir("install_one")
      local out, code = harness.cli({"install", "--dir", dir, "cursor"})
      assert_equal(code, 0, out)
      assert_true(read(dir .. "/.cursor/rules/luasec.mdc"), "cursor written")
      assert_equal(read(dir .. "/AGENTS.md"), nil, "agents not written")
      os.execute("rm -rf " .. string.format("%q", dir))
   end)

   it("refuses an unknown target", function()
      local out, code = harness.cli({"install", "vscode"})
      assert_equal(code, 2, out)
      assert_match(out, "claude, cursor, agents", out)
   end)

   it("treats a --dir with shell syntax in it as a directory name", function()
      -- Single-quoted by hand: harness.cli quotes with %q, and the shell that
      -- runs it would expand the $( ) before luasec ever saw it.
      local base = harness.scratch_dir("install_quote")
      local dir = base .. "/$(touch pwned)"
      local pipe = assert(io.popen(("cd '%s' && '%s/bin/luasec' install --dir '%s' cursor 2>&1; echo \"__EXIT__$?\"")
         :format(base, io.popen("pwd"):read("*l"), dir)))
      local out = pipe:read("*a")
      pipe:close()
      local pwned = io.open(base .. "/pwned", "rb")
      if pwned then pwned:close() end
      local written = read(dir .. "/.cursor/rules/luasec.mdc")
      os.execute(("rm -rf '%s'"):format(base))
      assert_match(out, "__EXIT__0", out)
      assert_true(pwned == nil, "the directory name ran as a command")
      assert_true(written, "the rule was written under the literal name")
   end)
end)
