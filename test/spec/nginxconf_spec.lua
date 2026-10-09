-- Lua embedded in an nginx.conf (#296): `*_by_lua_block` bodies are scanned, findings map back to
-- the nginx.conf's own line and column, and nothing else in the file is read as Lua.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luasec.api"
local nginxconf = require "luasec.cli.nginxconf"
local walk = require "luasec.cli.walk"

local function write(path, text)
   local handle = assert(io.open(path, "w"))
   handle:write(text)
   handle:close()
end

local function scan(text)
   local dir = os.tmpname()
   os.remove(dir)
   os.execute("mkdir -p '" .. dir .. "'")
   local path = dir .. "/nginx.conf"
   write(path, text)
   local report = api.analyze({path})
   os.remove(path)
   os.remove(dir)
   return report
end

local HANDLER = table.concat({
   "http {",                                                  -- 1
   "  server {",                                              -- 2
   "    location = /run {",                                   -- 3
   "      content_by_lua_block {",                            -- 4
   "        local host = ngx.req.get_uri_args().h",           -- 5
   "        os.execute('ping ' .. host)",                     -- 6
   "      }",                                                 -- 7
   "    }",                                                   -- 8
   "  }",                                                     -- 9
   "}", ""}, "\n")

describe("Lua in an nginx.conf (#296)", function()
   it("reports a tainted ngx source at the nginx.conf's own line and column", function()
      local report = scan(HANDLER)
      assert_equal(#report, 1, "one 709 from the handler")
      assert_equal(report[1].code, "709")
      assert_equal(report[1].line, 6, "os.execute is on line 6 of the conf, not of the block")
      assert_equal(report[1].column, HANDLER:match("[^\n]*os%.execute"):find("os.execute", 1, true))
   end)

   it("reports nothing for a safe handler and for a conf with no Lua block", function()
      assert_equal(#scan("location = /ok { content_by_lua_block { ngx.say('hi') } }"), 0)
      assert_equal(#scan("# content_by_lua_block { os.execute(ngx.var.arg_x) }\nlisten 80;\n"), 0,
         "a commented-out block is not a block")
   end)

   it("does not end a block at a brace inside a Lua string or comment", function()
      local text = 'location / { content_by_lua_block {\n' ..
         '  local s = "}" -- }\n  --[[ } ]] local t = [[ } ]]\n' ..
         '  os.execute(ngx.var.arg_x)\n} }\n'
      local report = scan(text)
      assert_equal(#report, 1)
      assert_equal(report[1].line, 4)
   end)

   it("lets a handler end in return, and scans every block of a file", function()
      local text = "location /a { access_by_lua_block { return ngx.exit(403) } }\n" ..
         "location /b { content_by_lua_block { os.execute(ngx.var.arg_x) } }\n"
      local report = scan(text)
      assert_equal(#report, 1, "a `return` in one block must not break the next")
      assert_equal(report[1].line, 2)
   end)

   it("extract keeps every line and the columns before each block's closer, and blanks the rest", function()
      local out = nginxconf.extract(HANDLER)
      assert_equal(select(2, out:gsub("\n", "")), select(2, HANDLER:gsub("\n", "")))
      assert_true(not out:find("server", 1, true), "nginx directives are blanked")
   end)

   it("the walk selects a .conf only when it holds a block", function()
      local dir = os.tmpname()
      os.remove(dir)
      os.execute("mkdir -p '" .. dir .. "'")
      write(dir .. "/with.conf", HANDLER)
      write(dir .. "/without.conf", "worker_processes 1;\n")
      local files = walk.collect({dir})
      os.remove(dir .. "/with.conf")
      os.remove(dir .. "/without.conf")
      os.remove(dir)
      assert_equal(#files, 1)
      assert_true(files[1]:find("with.conf", 1, true) ~= nil)
   end)

   it("reads the authored conf the way the corpus does: ten findings, all on conf lines", function()
      local report = api.analyze({"test/fixtures/openresty-authored/nginx.conf"})
      assert_equal(#report, 10, "the count docs/precision.md and the golden record for #296")
   end)
end)
