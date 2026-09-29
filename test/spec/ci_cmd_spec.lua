local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match = harness.assert_equal, harness.assert_match

local version = require "luasec.version"

local function read(path)
   local handle = io.open(path, "rb")
   if not handle then return nil end
   local text = handle:read("*a")
   handle:close()
   return text
end

describe("luasec ci install", function()
   it("writes a workflow that runs the luasec action at this version", function()
      local dir = harness.scratch_dir("ci_install")
      local out, code = harness.cli({"ci", "install", "--dir", dir})
      local workflow = read(dir .. "/.github/workflows/luasec.yml")
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 0, out)
      assert_match(workflow, "uses: Vaibhav91one/luasec@v" .. version.luasec:gsub("%p", "%%%0"), workflow)
      assert_match(workflow, "security%-events: write", workflow)
      assert_match(out, "wrote .*/%.github/workflows/luasec%.yml", out)
   end)

   it("does not overwrite an existing workflow without --force", function()
      local dir = harness.scratch_dir("ci_exists")
      os.execute(("mkdir -p %q"):format(dir .. "/.github/workflows"))
      local handle = assert(io.open(dir .. "/.github/workflows/luasec.yml", "w"))
      handle:write("mine\n")
      handle:close()
      local out, code = harness.cli({"ci", "install", "--dir", dir})
      local kept = read(dir .. "/.github/workflows/luasec.yml")
      local _, forced_code = harness.cli({"ci", "install", "--dir", dir, "--force"})
      local forced = read(dir .. "/.github/workflows/luasec.yml")
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 2, out)
      assert_match(out, "already exists", out)
      assert_equal(kept, "mine\n", "left alone")
      assert_equal(forced_code, 0, "forced")
      assert_match(forced, "Vaibhav91one/luasec@", "replaced with --force")
   end)

   it("refuses an unknown ci command", function()
      local out, code = harness.cli({"ci", "run"})
      assert_equal(code, 2, out)
      assert_match(out, "expected install", out)
   end)

   it("treats a --dir with shell syntax in it as a directory name", function()
      -- Single-quoted by hand: harness.cli quotes with %q, and the shell that
      -- runs it would expand the $( ) before luasec ever saw it.
      local base = harness.scratch_dir("ci_quote")
      local dir = base .. "/$(touch pwned)"
      local pipe = assert(io.popen(("cd '%s' && '%s/bin/luasec' ci install --dir '%s' 2>&1; echo \"__EXIT__$?\"")
         :format(base, io.popen("pwd"):read("*l"), dir)))
      local out = pipe:read("*a")
      pipe:close()
      local pwned = io.open(base .. "/pwned", "rb")
      if pwned then pwned:close() end
      local written = read(dir .. "/.github/workflows/luasec.yml")
      os.execute(("rm -rf '%s'"):format(base))
      assert_match(out, "__EXIT__0", out)
      assert_equal(pwned, nil, "the directory name ran as a command")
      assert_match(written, "Vaibhav91one/luasec@", "written under the literal name")
   end)
end)
