local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_nil, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_nil, harness.assert_true

-- Drive selector.pick with `keys` as the bytes io.read(1) returns.
local function drive_pick(title, items, keys, opts)
   local selector = require "luadoctor.cli.selector"
   local saved_read = io.read
   local pos = 0
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
   local ok, picked = pcall(selector.pick, {out = out}, title, items, opts)
   io.read = saved_read
   assert(ok, "selector.pick raised: " .. tostring(picked))
   return picked, table.concat(chunks)
end

local function items()
   return {
      {key = "a", label = "first"},
      {key = "b", label = "second"},
      {key = "c", label = "third"},
   }
end

describe("selector.pick", function()
   it("moves down twice and selects the third item on Enter", function()
      local picked = drive_pick("Pick", items(), "\27[B\27[B\r")
      assert_equal(picked, 3, "down/down/Enter")
   end)

   it("wraps k past the top and j past the bottom", function()
      assert_equal(drive_pick("Pick", items(), "k\r"), 3, "k from row 1 wraps to row 3")
      assert_equal(drive_pick("Pick", items(), "\27[A\r"), 3, "Up from row 1 wraps to row 3")
      assert_equal(drive_pick("Pick", items(), "j\r", {initial = 3}), 1, "j from row 3 wraps to row 1")
   end)

   it("goes back on Esc, q, Ctrl-C, Ctrl-D and closed stdin", function()
      assert_nil(drive_pick("Pick", items(), "\27"), "bare Esc")
      assert_nil(drive_pick("Pick", items(), "q"), "q")
      assert_nil(drive_pick("Pick", items(), "\3"), "Ctrl-C")
      assert_nil(drive_pick("Pick", items(), "\4"), "Ctrl-D")
      assert_nil(drive_pick("Pick", items(), ""), "closed stdin returns nil without hanging")
   end)

   it("jumps straight to an item's key letter", function()
      assert_equal(drive_pick("Pick", items(), "b"), 2, "the key letter selects at once")
   end)

   it("marks the recommended row once and shows the hint line", function()
      local flagged = {
         {key = "a", label = "first"},
         {key = "b", label = "second", recommended = true},
         {key = "c", label = "third"},
      }
      local picked, out = drive_pick("Pick", flagged, "\r", {initial = 2})
      assert_equal(picked, 2, "Enter keeps the initial row")
      assert_match(out, "> b  second %(Recommended%)", out)
      local _, marks = out:gsub("%(Recommended%)", "")
      assert_equal(marks, 1, "exactly one row is recommended: " .. out)
      assert_true(out:find("↑/↓ move · Enter select · Esc back · q quit", 1, true) ~= nil,
         "the hint line is shown: " .. out)
   end)
end)
