local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local version = require "luasec.version"

local function load_rockspec(path)
   local handle = assert(io.open(path, "rb"), path .. " is missing")
   local text = handle:read("*a")
   handle:close()
   local env = {}
   assert(load(text, "@" .. path, "t", env))()
   return env
end

local function lua_files(dir)
   local found = {}
   local pipe = assert(io.popen(("find %q -name '*.lua' -type f"):format(dir)))
   for path in pipe:lines() do found[path] = true end
   pipe:close()
   return found
end

describe("rockspec", function()
   local path = "luasec-scanner-" .. version.luasec .. "-1.rockspec"

   it("exists for this version and names the rock luasec-scanner", function()
      local spec = load_rockspec(path)
      assert_equal(spec.package, "luasec-scanner", "luasec is LuaSec's name on LuaRocks")
      assert_equal(spec.version, version.luasec .. "-1", "version")
      assert_equal(spec.build.install.bin.luasec, "bin/luasec.lua", "installs the luasec command")
   end)

   it("lists every module under src/ and vendor/, and nothing else", function()
      local spec = load_rockspec(path)
      local expected = lua_files("src")
      for file in pairs(lua_files("vendor/luacheck")) do expected[file] = true end
      local listed = {}
      for name, file in pairs(spec.build.modules) do
         listed[file] = true
         assert_true(expected[file], "rockspec lists " .. file .. " which does not exist")
         local want = file:gsub("^src/", ""):gsub("^vendor/", ""):gsub("%.lua$", ""):gsub("/init$", "")
            :gsub("/", ".")
         assert_equal(name, want, "module name for " .. file)
      end
      for file in pairs(expected) do
         assert_true(listed[file], file .. " is not in the rockspec")
      end
   end)
end)
