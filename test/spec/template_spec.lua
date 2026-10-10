-- CGILua pages: Lua inside <?lua ?> blocks in .html/.htm files, and inside
-- <?lua ?> / <% %> / <%= %> blocks in .lp files, is scanned with its HTML
-- blanked but its lines and columns kept, so a finding lands on the page's
-- own line. LuCI's <%: %> / <%+ %> / <%# %> dialect is not Lua and is skipped.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match, assert_no_match =
   harness.assert_equal, harness.assert_true, harness.assert_match, harness.assert_no_match

local api = require "luadoctor.api"

local T = "test/fixtures/template/"

local function read(path)
   local handle = assert(io.open(path, "rb"))
   local text = handle:read("*a")
   handle:close()
   return text
end

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

local function write(path, text)
   local handle = assert(io.open(path, "w"))
   handle:write(text)
   handle:close()
end

describe("template pages", function()
   it("reports tainted data in a <?lua block as 709 on the page's own line", function()
      local report = api.analyze({T .. "handler.html"})
      assert_equal(codes(report), "709", "one 709 from the block")
      assert_equal(report[1].line, 5, "the os.execute call is on line 5 of the page")
      assert_equal(report[1].file, T .. "handler.html", "the finding names the page")
   end)

   it("keeps the column of a sink inside a block", function()
      local text = read(T .. "columns.html")
      local line2 = text:match("[^\n]*\n([^\n]*)")
      local want = assert(line2:find("os.execute", 1, true),
         "the fixture holds os.execute on its second line")
      local report = api.analyze({T .. "columns.html"})
      assert_equal(codes(report), "709", "one 709 from the block")
      assert_equal(report[1].line, 2, "line count is preserved")
      assert_equal(report[1].column, want, "the column matches the page, not the extraction")
   end)

   it("analyses a <%= expression block in a .lp page", function()
      local report = api.analyze({T .. "expr.lp"})
      assert_equal(codes(report), "709", "the expression block is Lua, not text")
      assert_equal(report[1].line, 4, "the sink is on line 4 of the page")
      assert_equal(report[1].file, T .. "expr.lp", "the finding names the page")
   end)

   it("analyses a <% statement block in a .lp page", function()
      local report = api.analyze({T .. "stmt.lp"})
      assert_equal(codes(report), "709", "the statement block is Lua, not text")
      assert_equal(report[1].line, 4, "the sink is on line 4 of the page")
      assert_equal(report[1].file, T .. "stmt.lp", "the finding names the page")
   end)

   it("skips a LuCI-dialect .htm page: <%: %> is translation, not Lua", function()
      local report = api.analyze({T .. "luci.htm"})
      assert_equal(#report, 0, "no block lua-doctor reads means nothing analysed, no 901")
      local dir = harness.scratch_dir("template_luci_walk")
      write(dir .. "/view.htm", read(T .. "luci.htm"))
      local out, code = harness.cli({dir})
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 0, out)
      assert_no_match(out, "901", "a skipped page is not a coverage gap: " .. out)
      assert_true(not out:find("view.htm", 1, true), "the page is not scanned: " .. out)
   end)

   it("leaves .lp pages to explicit paths: a walk never collects them", function()
      -- The precision denominator counts what the walk collects; .lp pages are
      -- analysed when named (see above) but never gathered from a directory.
      local dir = harness.scratch_dir("template_lp_walk")
      write(dir .. "/page.lp", read(T .. "stmt.lp"))
      local out, code = harness.cli({dir})
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 0, out)
      assert_no_match(out, "901", "a skipped page is not a coverage gap: " .. out)
      assert_true(not out:find("page.lp", 1, true), "the page is not scanned: " .. out)
   end)

   it("never analyses text outside blocks", function()
      local report = api.analyze({T .. "decoy.html"})
      assert_equal(#report, 0, "os.execute in HTML text and script is not code")
   end)

   it("reports nothing, not even a 901, for a page with no Lua block", function()
      local report = api.analyze({T .. "plain.html"})
      assert_equal(#report, 0, "a page with no block is not analysed at all")
   end)

   it("reports an untainted dynamic command in a block as 701 on the page line", function()
      local report = api.analyze({T .. "exec.html"})
      assert_equal(codes(report), "701", "one 701 from the block")
      assert_equal(report[1].line, 4, "the os.execute call is on line 4 of the page")
      assert_equal(report[1].file, T .. "exec.html", "the finding names the page")
   end)

   it("walks a directory: a page with a block is in, a plain page is out", function()
      local dir = harness.scratch_dir("template_walk")
      write(dir .. "/page.html", read(T .. "handler.html"))
      write(dir .. "/plain.html", read(T .. "plain.html"))
      os.execute("ln -sfn nowhere " .. string.format("%q", dir .. "/dangling.html"))
      local out, code = harness.cli({dir})
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 1, out)
      assert_match(out, "page%.html:5", out)
      assert_match(out, "709", out)
      assert_true(not out:find("plain.html", 1, true), "a page with no block is skipped: " .. out)
      assert_no_match(out, "901", "a dangling .html link is not a coverage gap: " .. out)
   end)

   it("explains a template finding against the HTML line", function()
      local out, code = harness.cli({"why", T .. "handler.html:5"})
      assert_equal(code, 0, out)
      assert_match(out, "%[709%]", out)
      assert_match(out, "os%.execute%(\"ping %-c1", out, "the frame shows the HTML line: " .. out)
   end)

   it("fingerprints a template finding by its page, not its lines", function()
      local dir = harness.scratch_dir("template_baseline")
      write(dir .. "/same.lua", 'local h = http.formvalue("h")\nos.execute("ping " .. h)\n')
      write(dir .. "/same.html", '<html>\n<?lua\nlocal h = http.formvalue("h")\nos.execute("ping " .. h)\n?>\n</html>\n')
      local _, write_code = harness.cli({"--format", "json", "-o", dir .. "/base.json", dir .. "/same.lua"})
      assert_equal(write_code, 1, "the .lua file holds a 709")
      local out, code = harness.cli({"--baseline", dir .. "/base.json",
         dir .. "/same.lua", dir .. "/same.html"})
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 3, "the page finding is new although the .lua one is known: " .. out)
      assert_match(out, "same%.html", out)
      assert_true(not out:find("same.lua", 1, true), "the known .lua finding stays suppressed: " .. out)
   end)

   it("picks a staged template page up with --staged", function()
      local dir = harness.scratch_dir("template_staged")
      local function q(text) return string.format("%q", text) end
      local function sh(command)
         local pipe = assert(io.popen(("cd %s && %s 2>&1"):format(q(dir), command)))
         local out = pipe:read("*a")
         pipe:close()
         return out
      end
      sh("git init -q && git config user.email t@t && git config user.name t")
      write(dir .. "/page.html", read(T .. "handler.html"))
      sh("git add page.html")
      local root = io.popen("pwd"):read("*l")
      local pipe = assert(io.popen(("cd %s && %s --staged 2>&1; printf '\\n__EXIT__%%d' $?")
         :format(q(dir), q(root .. "/bin/lua-doctor"))))
      local out = pipe:read("*a")
      pipe:close()
      local code = tonumber(out:match("__EXIT__(%d+)%s*$"))
      os.execute("rm -rf " .. q(dir))
      assert_equal(code, 1, out)
      assert_match(out, "page%.html", out)
   end)
end)
