local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_no_match =
   harness.assert_equal, harness.assert_match, harness.assert_no_match

local TAINTED = "test/fixtures/tainted_exec/handler.lua"

local function with_config(tag, text, args)
   local dir = harness.scratch_dir(tag)
   local path = dir .. "/lua-doctor.config.lua"
   local f = assert(io.open(path, "w"))
   f:write(text)
   f:close()
   local full = {"--config", path}
   for _, a in ipairs(args) do full[#full + 1] = a end
   local out, code = harness.cli(full)
   os.execute("rm -rf " .. string.format("%q", dir))
   return out, code
end

describe("config file", function()
   it("rejects an unknown key and lists the valid ones", function()
      local out, code = with_config("cfg_unknown", "return {fail_onn = 'high'}", {TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "unknown key 'fail_onn'", out)
      assert_match(out, "allow, disable, fail_on, severity, std", out)
   end)

   it("refuses an allow entry without a reason", function()
      local out, code = with_config("cfg_noreason", "return {allow = {{code = '709'}}}", {TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "allow%[1%] needs a reason", out)
   end)

   it("refuses a code lua-doctor does not have", function()
      local out, code = with_config("cfg_badcode", "return {severity = {['799'] = 'low'}}", {TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "'799' is not a lua%-doctor code", out)
   end)

   it("cannot run code: the file sees no globals", function()
      local out, code = with_config("cfg_env", "os.execute('true') return {}", {TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "cannot use config", out)
   end)

   it("disables a code like --ignore", function()
      local out, code = with_config("cfg_disable", "return {disable = {'709'}}", {TAINTED})
      assert_equal(code, 0, out)
      assert_no_match(out, "%[709%]", out)
   end)

   it("overrides a severity before --fail-on is applied", function()
      local out, code = with_config("cfg_sev", "return {severity = {['709'] = 'low'}}",
         {"--fail-on", "high", TAINTED})
      assert_equal(code, 0, out)
      assert_match(out, "%[709%] low", out)
   end)

   it("lets the command line win over the config's fail_on", function()
      local out, code = with_config("cfg_failon", "return {fail_on = 'critical'}",
         {"--fail-on", "low", TAINTED})
      assert_equal(code, 1, out)
   end)

   it("allows a finding with a reason and says so", function()
      local out, code = with_config("cfg_allow",
         "return {allow = {{code = '709', file = 'handler.lua', reason = 'test fixture'}}}", {TAINTED})
      assert_equal(code, 0, out)
      assert_no_match(out, "%[709%] critical", out)
      assert_match(out, "allowed 1 finding%(s%) of 709 in handler.lua: test fixture", out)
   end)

   it("says when an allow entry matched nothing", function()
      local out = with_config("cfg_stale",
         "return {allow = {{code = '701', reason = 'old'}}}", {TAINTED})
      assert_match(out, "config allow for 701 in any file matched nothing", out)
   end)

   it("fails on a --config file that does not exist", function()
      local out, code = harness.cli({"--config", "/nonexistent/lua-doctor.config.lua", TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "cannot read config", out)
   end)

   it("loads lua-doctor.config.lua from the current directory unless --no-config", function()
      local dir = harness.scratch_dir("cfg_auto")
      local f = assert(io.open(dir .. "/lua-doctor.config.lua", "w"))
      f:write("return {disable = {'709'}}")
      f:close()
      local root = io.popen("pwd"):read("*l")
      local function run(extra)
         local pipe = assert(io.popen(("cd %q && %q %s %q 2>&1; printf '\\n__EXIT__%%d' $?")
            :format(dir, root .. "/bin/lua-doctor", extra, root .. "/" .. TAINTED)))
         local out = pipe:read("*a")
         pipe:close()
         return out
      end
      local auto, skipped = run(""), run("--no-config")
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_no_match(auto, "%[709%]", auto)
      assert_match(skipped, "%[709%]", skipped)
      assert_match(auto, "lua%-doctor: using lua%-doctor%.config%.lua from the current directory", auto)
   end)

   it("never runs the file: a statement in it is refused, not executed", function()
      -- A bounded loop, so a build that still runs the file fails this spec
      -- instead of hanging on it.
      local out, code = with_config("cfg_loop", "for i = 1, 3 do end return {}", {TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "cannot use config", out)
   end)

   it("refuses a computed value", function()
      local out, code = with_config("cfg_calc", "return {fail_on = ('hi'):rep(1) .. 'gh'}", {TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "only literal", out)
   end)

   it("refuses a severity key that is a number, not a quoted code", function()
      local out, code = with_config("cfg_numkey", "return {severity = {[709] = 'low'}}", {TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "quoted", out)
   end)

   it("still reads every documented key", function()
      local out, code = with_config("cfg_full", [[
return {
  std = "+openwrt+luci",
  fail_on = "critical",
  disable = {"705"},
  severity = {["709"] = "high"},
  allow = {{code = "701", file = "x.lua", reason = "reviewed"}},
}
]], {TAINTED})
      assert_equal(code, 0, out)
      assert_match(out, "%[709%] high", out)
   end)
end)
