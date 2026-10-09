-- Return-value and container taint (#317, and the rest of #309).
--
-- A value reaches a sink through a function's return, a table the function
-- built, or the elements of a list. Each flow below has a clean twin: a
-- sanitizer on the return path, a constant return, an untainted append, a field
-- read that is not the tainted field.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true, assert_equal = harness.assert_true, harness.assert_equal

local api = require "luasec.api"

local function find(report, code)
   for _, finding in ipairs(report) do
      if finding.code == code then return finding end
   end
end

local function scan(source, std)
   return api.check_source(source, {std = std or "openwrt+luci"})
end

local function luci_file(tag, subdir, name, body)
   local dir = harness.scratch_dir(tag) .. "/root/usr/lib/lua/luci/" .. subdir
   os.execute(("mkdir -p %q"):format(dir))
   local path = dir .. "/" .. name
   local handle = assert(io.open(path, "w"))
   handle:write(body)
   handle:close()
   return path
end

describe("table appends make the table tainted (container level)", function()
   it("follows argv[#argv+1] = v into a command built from the table", function()
      local report = scan([[
local function run()
   local argv = {"ls"}
   argv[#argv + 1] = luci.http.formvalue("a")
   os.execute(table.concat(argv, " "))
end
]])
      assert_true(find(report, "709") ~= nil, "expected a 709")
   end)

   it("follows table.insert(t, v)", function()
      local report = scan([[
local function run()
   local t = {}
   table.insert(t, luci.http.formvalue("a"))
   os.execute(table.concat(t, " "))
end
]])
      assert_true(find(report, "709") ~= nil, "expected a 709")
   end)

   it("follows a computed-key store, t[k] = v", function()
      local report = scan([[
local function run(k)
   local t = {}
   t[k] = luci.http.formvalue("a")
   os.execute(table.concat(t, " "))
end
]])
      assert_true(find(report, "709") ~= nil, "expected a 709")
   end)

   it("follows the elements out again through a for-in loop", function()
      local report = scan([[
local function run()
   local list = {}
   list[#list + 1] = luci.http.formvalue("a")
   for _, item in ipairs(list) do
      os.execute(item)
   end
end
]])
      assert_true(find(report, "709") ~= nil, "expected a 709")
   end)

   it("does not report a table that only received constants", function()
      local report = scan([[
local function run()
   local argv = {}
   argv[#argv + 1] = "ls"
   table.insert(argv, "-l")
   os.execute(table.concat(argv, " "))
end
]])
      assert_true(find(report, "709") == nil, "an untainted append is not a flow")
   end)

   it("keeps a named field exact: a constant field is not tainted by its sibling", function()
      local report = scan([[
local function run()
   local t = {}
   t.cmd = luci.http.formvalue("a")
   t.safe = "ls"
   os.execute(t.safe)
end
]])
      assert_true(find(report, "709") == nil, "t.safe was never written from a request")
   end)

   it("taints the whole table when a named-field table is used as a whole", function()
      local report = scan([[
local function run()
   local t = {}
   t.cmd = luci.http.formvalue("a")
   os.execute(table.concat(t, " "))
end
]])
      assert_true(find(report, "709") ~= nil, "expected a 709")
   end)
end)

describe("a function that returns a table it built", function()
   local PARSE = [[
local function parse(url)
   local parsed = {}
   parsed.path = url
   return parsed
end
]]

   it("carries the argument's taint to a field read of the result", function()
      local report = scan(PARSE .. [[
local function run()
   local u = parse(luci.http.formvalue("x"))
   os.execute("ls " .. u.path)
end
]])
      assert_true(find(report, "709") ~= nil, "expected a 709")
   end)

   it("stays clean for a caller that passes a constant", function()
      local report = scan(PARSE .. [[
local function run()
   local u = parse("fixed")
   os.execute("ls " .. u.path)
end
]])
      assert_true(find(report, "709") == nil, "a constant argument is not request data")
   end)

   it("stays clean for a constant return", function()
      local report = scan([[
local function name(x)
   local t = {}
   t.n = "ls"
   return t
end
local function run()
   local u = name(luci.http.formvalue("x"))
   os.execute(u.n)
end
]])
      assert_true(find(report, "709") == nil, "the table never held the argument")
   end)

   it("reports a quoted value one step down, not as a bare flow", function()
      local report = scan([[
local function quote(x)
   return luci.util.shellquote(x)
end
local function run()
   os.execute("echo " .. quote(luci.http.formvalue("x")))
end
]])
      local finding = find(report, "709")
      assert_true(finding == nil or finding.sanitizer == "shell-quoted",
         "a value that went through the quoting helper on the return path is not a bare 709")
   end)
end)

describe("a module function's table, followed across files (--whole-program)", function()
   local function scan_two(lib_body, user_body)
      local lib = luci_file("rt_lib", "tools", "ddns.lua", lib_body)
      local user = luci_file("rt_user", "model/cbi", "d.lua", user_body)
      return api.analyze({lib, user}, {std = "luci", whole_program = true,
         whole_program_basename = true})
   end

   local LIB = [[
module("luci.tools.ddns", package.seeall)
function parse_url(url)
   local parsed = {}
   parsed.path = url
   return parsed
end
function fixed_url(url)
   local parsed = {}
   parsed.path = "/fixed"
   return parsed
end
]]

   it("reports a value read from the returned table's field", function()
      local report = scan_two(LIB, [[
local DDNS = require "luci.tools.ddns"
local SYS = require "luci.sys"
function uurl.validate(self, value)
   local url = DDNS.parse_url(value)
   SYS.call("nslookup " .. url.path)
end
]])
      assert_true(find(report, "709") ~= nil, "expected a 709 through DDNS.parse_url")
   end)

   it("does not report a returned table that never held the argument", function()
      local report = scan_two(LIB, [[
local DDNS = require "luci.tools.ddns"
local SYS = require "luci.sys"
function uurl.validate(self, value)
   local url = DDNS.fixed_url(value)
   SYS.call("nslookup " .. url.path)
end
]])
      assert_true(find(report, "709") == nil, "fixed_url ignores its argument")
   end)
end)

describe("the commands.lua shape: a dispatcher's ... parsed into argv", function()
   local SOURCE = [[
local function parse_args(str)
   local args = {}
   local function put(bytes)
      local chunks = {}
      local chr = string.char
      local upk = unpack
      for off = 1, #bytes, 256 do
         chunks[#chunks + 1] = chr(upk(bytes, off, 4))
      end
      args[#args + 1] = table.concat(chunks)
   end
   local res = {}
   for off = 1, #str do
      res[#res + 1] = str:byte(off)
   end
   put(res)
   return args
end

local function parse_cmdline(cmdid, args)
   local argv = parse_args("ls")
   if args then
      for _, v in ipairs(parse_args(luci.http.urldecode(args))) do
         argv[#argv + 1] = v
      end
   end
   return argv
end

function execute_command(callback, ...)
   local argv = parse_cmdline(...)
   os.execute(table.concat(argv, " ") .. " >/dev/null")
end

function call_it()
   execute_command(print, "id", luci.http.formvalue("q"))
end
]]

   it("reports the command built from the appended elements as 709", function()
      local report = scan(SOURCE)
      local finding = find(report, "709")
      assert_true(finding ~= nil, "expected a 709")
      assert_equal("os.execute", finding.sink)
   end)

   it("is silent when the caller passes only constants", function()
      local clean = SOURCE:gsub('luci%.http%.formvalue%("q"%)', '"fixed"')
      assert_true(find(scan(clean), "709") == nil, "no request data reaches the command")
   end)
end)

describe("string methods and nested calls", function()
   it("treats str:sub() like string.sub(str)", function()
      local report = scan([[
local function run()
   local s = luci.http.formvalue("a")
   os.execute(s:sub(1, 5))
end
]])
      assert_true(find(report, "709") ~= nil, "expected a 709")
   end)

   it("binds a callee reached only through another call's arguments", function()
      local report = scan([[
local function wrap(c)
   os.execute(c)
   return ""
end
local function run()
   print(wrap(luci.http.formvalue("a")))
end
]])
      assert_true(find(report, "709") ~= nil, "wrap's sink is fed by the nested call")
   end)
end)

describe("a factory that returns a UCI cursor is a config handle (#317)", function()
   local function secrets(source)
      local n = 0
      for _, finding in ipairs(scan(source)) do
         if finding.code == "747" then n = n + 1 end
      end
      return n
   end

   it("recognises a local factory", function()
      assert_equal(1, secrets([[
local uci = require "luci.model.uci"
local function open_section() return uci.cursor() end
local c = open_section()
c:set("system", "admin", "password", "hunter2hunter2")
]]))
   end)

   it("recognises a global factory, called inline", function()
      assert_equal(1, secrets([[
function open_section() return require("uci").cursor() end
open_section():set("system", "admin", "password", "hunter2hunter2")
]]))
   end)

   it("recognises a module-field factory and a factory behind a variable", function()
      assert_equal(2, secrets([[
local uci = require "luci.model.uci"
local M = {}
function M.open() local c = uci.cursor(); return c end
M.open():set("system", "admin", "password", "hunter2hunter2")
local h = M.open()
h:set("system", "admin", "psk", "zzzzzzzzzzzz1234")
]]))
   end)

   it("does not take another library's cursor factory for a config handle", function()
      assert_equal(0, secrets([[
local function open_db() return require("sqlite").cursor() end
open_db():set("system", "admin", "password", "hunter2hunter2")
]]))
   end)

   it("does not take a factory that returns a plain table for a config handle", function()
      assert_equal(0, secrets([[
local function make() return {} end
make():set("system", "admin", "password", "hunter2hunter2")
]]))
   end)

   it("terminates on a factory that returns its own call", function()
      assert_equal(0, secrets([[
local function loop() return loop() end
loop():set("system", "admin", "password", "hunter2hunter2")
]]))
   end)
end)

describe("bounds", function()
   it("does not re-expand a diamond of tables that each store the last one twice", function()
      local lines = {"local function go()", "  local t0 = {v = luci.http.formvalue('a')}"}
      for k = 1, 60 do
         lines[#lines + 1] = ("  local t%d = {}; t%d.a = t%d; t%d.b = t%d"):format(k, k, k - 1, k, k - 1)
      end
      lines[#lines + 1] = "  os.execute(t60)"
      lines[#lines + 1] = "end"
      local started = os.clock()
      local report = scan(table.concat(lines, "\n"))
      assert_true(os.clock() - started < 5, "60 stacked tables took too long")
      assert_true(find(report, "709") ~= nil, "the taint still arrives")
   end)
end)
