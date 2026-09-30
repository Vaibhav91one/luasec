local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true =
   harness.assert_equal, harness.assert_true

local term = require "luasec.cli.term"

local function dlen(text)
   if utf8 and utf8.len then
      return utf8.len(text) or #text
   end
   return #text
end

local function strip_esc(text)
   return (text:gsub("\27%[[%d;?]*[A-Za-z]", ""))
end

describe("term.fit", function()
   it("leaves short strings unchanged", function()
      assert_equal(term.fit("hello", 40), "hello", "short text is untouched")
   end)

   it("fits a 100-char path to 40 columns keeping the file:line tail", function()
      local tail = "file.lua:61"
      local path = "/" .. string.rep("a", 100 - #tail - 2) .. "/" .. tail
      assert_equal(#path, 100, "the fixture is 100 bytes")
      local fitted = term.fit_path(path, 40)
      assert_equal(dlen(fitted), 40, "fitted to 40 display columns")
      assert_true(fitted:find("…", 1, true) ~= nil, "the middle is marked: " .. fitted)
      assert_equal(fitted:sub(-#tail), tail, "the file:line tail survives: " .. fitted)
   end)

   it("never splits a multibyte character", function()
      local text = string.rep("é", 50)
      local fitted = term.fit(text, 40)
      assert_equal(dlen(fitted), 40, "fitted to 40 display columns")
      assert_true(utf8.len(fitted) ~= nil, "the result is valid UTF-8: " .. fitted)
   end)
end)

describe("term.wrap", function()
   it("breaks at spaces and no output line exceeds the width", function()
      local lines = term.wrap("alpha beta gamma delta epsilon zeta", 12)
      assert_true(#lines > 1, "long text wraps to several lines")
      for _, line in ipairs(lines) do
         assert_true(dlen(line) <= 12, "line fits: " .. line)
      end
      assert_true(lines[1]:find(" ", 1, true) == nil or lines[1] == "alpha beta",
         "breaks at a space: " .. lines[1])
   end)
end)

describe("term.width", function()
   it("honours COLUMNS through the parsing helper", function()
      assert_equal(term.parse_width("", "40"), 40, "COLUMNS=40 is honoured")
   end)

   it("falls back to 80 when COLUMNS is garbage", function()
      assert_equal(term.parse_width("", "banana"), 80, "garbage COLUMNS falls back")
      assert_equal(term.parse_width("", ""), 80, "empty COLUMNS falls back")
   end)
end)

describe("review rows fit a narrow terminal", function()
   it("never writes a list row longer than 39 display columns at COLUMNS=40", function()
      local dir = harness.scratch_dir("term_width_review")
      local long = dir .. "/" .. string.rep("d", 80) .. ".lua"
      local handle = assert(io.open(long, "wb"))
      handle:write("os.execute(arg[1])\n")
      handle:close()
      local out = harness.cli({"--interactive", long}, {env = "COLUMNS=40", stdin = "rqq"})
      os.execute("rm -rf " .. string.format("%q", dir))
      local clean = strip_esc(out)
      local saw_row = false
      for line in (clean .. "\n"):gmatch("([^\n]*)\n") do
         if line:match("^> ") or line:match("^  .*%.lua:%d") then
            saw_row = true
            assert_true(dlen(line) <= 39, "list row fits: " .. line)
         end
      end
      assert_true(saw_row, "a list row was shown: " .. clean)
   end)
end)

describe("review list rows keep their place", function()
   local function two_files(dir)
      local alpha = dir .. "/alpha.lua"
      local beta = dir .. "/beta.lua"
      local handle = assert(io.open(alpha, "wb"))
      handle:write("os.execute(arg[1])\n")
      handle:close()
      handle = assert(io.open(beta, "wb"))
      handle:write("-- pad\nos.execute(arg[1])\n")
      handle:close()
      return alpha, beta
   end

   local function list_rows(out)
      local rows = {}
      for line in (strip_esc(out) .. "\n"):gmatch("([^\n]*)\n") do
         if line:match("^[> ] %d%d%d  ") then
            rows[#rows + 1] = line
         end
      end
      return rows
   end

   it("at COLUMNS=60 every row fits, names its file and line, and rows differ", function()
      local dir = harness.scratch_dir("term_width_place")
      local alpha, beta = two_files(dir)
      local out = harness.cli({"--interactive", alpha, beta}, {env = "COLUMNS=60", stdin = "rqq"})
      os.execute("rm -rf " .. string.format("%q", dir))
      local rows = list_rows(out)
      assert_equal(#rows, 2, "both findings are listed: " .. strip_esc(out))
      for _, row in ipairs(rows) do
         assert_true(dlen(row) <= 59, "row fits: " .. row)
      end
      local seen_alpha, seen_beta
      for _, row in ipairs(rows) do
         if row:find("alpha.lua", 1, true) then
            seen_alpha = row
            assert_true(row:find(":1", 1, true) ~= nil, "alpha row keeps :1: " .. row)
         elseif row:find("beta.lua", 1, true) then
            seen_beta = row
            assert_true(row:find(":2", 1, true) ~= nil, "beta row keeps :2: " .. row)
         end
      end
      assert_true(seen_alpha ~= nil, "alpha row names its file: " .. strip_esc(out))
      assert_true(seen_beta ~= nil, "beta row names its file: " .. strip_esc(out))
      assert_true(seen_alpha:sub(3) ~= seen_beta:sub(3), "the rows differ by place, not marker")
   end)

   it("at COLUMNS=200 the row still shows the full message", function()
      local dir = harness.scratch_dir("term_width_wide")
      local alpha, beta = two_files(dir)
      local out = harness.cli({"--interactive", alpha, beta}, {env = "COLUMNS=200", stdin = "rqq"})
      os.execute("rm -rf " .. string.format("%q", dir))
      local rows = list_rows(out)
      assert_equal(#rows, 2, "both findings are listed: " .. strip_esc(out))
      assert_true(rows[1]:find("command execution with a non-constant argument", 1, true) ~= nil
         or rows[2]:find("command execution with a non-constant argument", 1, true) ~= nil,
         "the full message survives when wide: " .. strip_esc(out))
   end)
end)

describe("selector rows fit a narrow terminal", function()
   it("never writes a selector row longer than the width minus 1", function()
      local selector = require "luasec.cli.selector"
      local saved_read = io.read
      local keys, pos = "\r", 0
      io.read = function()
         pos = pos + 1
         if pos > #keys then return nil end
         return keys:sub(pos, pos)
      end
      local chunks = {}
      local out = {
         write = function(_, ...)
            for _, part in ipairs({...}) do chunks[#chunks + 1] = tostring(part) end
         end,
         flush = function() end,
      }
      local long_label = string.rep("s", 100) .. "/file.lua:61"
      local ok, picked = pcall(selector.pick, {out = out},
         "Pick", {{key = "a", label = long_label}}, {})
      io.read = saved_read
      assert_true(ok, "selector.pick raised: " .. tostring(picked))
      local width = term.width()
      local clean = strip_esc(table.concat(chunks))
      local saw_row = false
      for line in (clean .. "\n"):gmatch("([^\n]*)\n") do
         if line:match("^> ") or line:match("^  ") then
            saw_row = true
            assert_true(dlen(line) <= width - 1, "selector row fits: " .. line)
         end
      end
      assert_true(saw_row, "a selector row was shown: " .. clean)
   end)
end)
