-- 729: request data written to a declared store and read back into a command.
-- Neither half is a finding alone; the pairing after the scan decides, so a scan
-- with no tainted write reports exactly what it reported before.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luasec.api"
local profiles = require "luasec.registry.profiles"

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

local function count(report, code)
   local n = 0
   for _, finding in ipairs(report) do if finding.code == code then n = n + 1 end end
   return n
end

local function write_tmp(content)
   local path = os.tmpname()
   local handle = assert(io.open(path, "w"))
   handle:write(content)
   handle:close()
   return path
end

local WRITE = 'db.setAttribute("system", "_ROWID_", "1", "hostname", cgi["hostname"])\n'
local READ = 'local name = db.getAttribute("system", "_ROWID_", "1", "hostname")\nos.execute("hostname " .. name)\n'

describe("store hop (729)", function()
   it("reports a request value written to a store and read back into a command", function()
      local report = api.check_source(WRITE .. READ, {std = "cgilua"})
      assert_equal(count(report, "729"), 1, codes(report))
      local finding
      for _, f in ipairs(report) do if f.code == "729" then finding = f end end
      assert_equal(finding.source, "cgi")
      assert_equal(finding.confidence, "medium", "a named column pairs at medium")
      assert_match(finding.message, "system%.hostname")
      assert_match(finding.message, "written from cgi at line 1")
   end)

   it("replaces the dynamic-command finding at that site rather than adding to it", function()
      local before = api.check_source(READ, {std = "cgilua"})
      local after = api.check_source(WRITE .. READ, {std = "cgilua"})
      assert_true(count(before, "701") + count(before, "702") >= count(after, "701") + count(after, "702"),
         "no new 701/702: " .. codes(after))
   end)

   it("reports nothing new when nothing writes request data there", function()
      local alone = api.check_source(READ, {std = "cgilua"})
      assert_equal(count(alone, "729"), 0, codes(alone))
      local constant = api.check_source(
         'db.setAttribute("system", "_ROWID_", "1", "hostname", "router")\n' .. READ, {std = "cgilua"})
      assert_equal(count(constant, "729"), 0, "a constant write: " .. codes(constant))
   end)

   it("pairs only the same table and column", function()
      local other_column = api.check_source(
         'db.setAttribute("system", "_ROWID_", "1", "timezone", cgi["tz"])\n' .. READ, {std = "cgilua"})
      assert_equal(count(other_column, "729"), 0, codes(other_column))
      local other_table = api.check_source(
         'db.setAttribute("network", "_ROWID_", "1", "hostname", cgi["h"])\n' .. READ, {std = "cgilua"})
      assert_equal(count(other_table, "729"), 0, codes(other_table))
   end)

   it("never pairs a table name computed at run time", function()
      local report = api.check_source(
         'db.setAttribute(cgi["t"], "_ROWID_", "1", "hostname", cgi["hostname"])\n' .. READ, {std = "cgilua"})
      assert_equal(count(report, "729"), 0, codes(report))
   end)

   it("pairs a row write and a row read on the same column, at medium confidence", function()
      local row = 'local row = {}\nrow["system.hostname"] = cgi["hostname"]\ndb.update("system", row, "1")\n'
      local read_row = 'local r = db.getRow("system", "_ROWID_", "1")\nos.execute("hostname " .. r["system.hostname"])\n'
      local report = api.check_source(row .. read_row, {std = "cgilua"})
      assert_equal(count(report, "729"), 1, codes(report))
      for _, f in ipairs(report) do
         if f.code == "729" then
            assert_equal(f.confidence, "medium", "both sides name the column")
         end
      end
   end)

   it("does not pair a row read of a different column than the row write set", function()
      -- The firmware false positive: a writer sets one column of a table, and a
      -- reader reads a different column of the same table back into a command.
      local row = 'local row = {}\nrow["dot11Radio.chanWidth"] = cgi["cw"]\ndb.update("dot11Radio", row, "1")\n'
      local read_other = 'local r = db.getRow("dot11Radio", "_ROWID_", "1")\nos.execute("wl " .. r["dot11Radio.interfaceName"])\n'
      local report = api.check_source(row .. read_other, {std = "cgilua"})
      assert_equal(count(report, "729"), 0, "different column must not pair: " .. codes(report))
   end)

   it("does not pair a column write with a whole-row read of a different column (setAttribute firmware shape)", function()
      -- setAttribute writes one literal column; getRowWhere reads the whole row;
      -- the sink uses a different column. This was 82 false positives on one
      -- firmware image.
      local write = 'db.setAttribute("dot11Radio", "interfaceName", "wl0", "chanWidth", cgi["cw"])\n'
      local read_other = 'local r = db.getRowWhere("dot11Radio", "radioNo=1", false)\nos.execute("wl " .. r["dot11Radio.interfaceName"])\n'
      local report = api.check_source(write .. read_other, {std = "cgilua"})
      assert_equal(count(report, "729"), 0, "whole-row read of another column must not pair: " .. codes(report))
   end)

   it("pairs a write in one file with a read in another, without --whole-program", function()
      local dir = "test/fixtures/store_hop"
      local report = api.analyze({dir .. "/writer.lua", dir .. "/reader.lua"}, {std = "cgilua"})
      assert_equal(count(report, "729"), 1, codes(report))
      for _, f in ipairs(report) do
         if f.code == "729" then
            assert_match(f.file, "reader%.lua$")
            assert_match(f.message, "writer%.lua:2")
         end
      end
      local alone = api.analyze({dir .. "/reader.lua"}, {std = "cgilua"})
      assert_equal(count(alone, "729"), 0, codes(alone))
   end)

   it("pairs across --jobs workers", function()
      local pipe = assert(io.popen("./bin/lua-doctor --no-progress --std cgilua --jobs 2 --format json "
         .. "test/fixtures/store_hop/writer.lua test/fixtures/store_hop/reader.lua 2>/dev/null"))
      local out = pipe:read("*a")
      pipe:close()
      assert_match(out, '"id": ?"729"')
   end)

   it("rejects a store declaration with a position that is not a number, or a write of two shapes", function()
      local bad = write_tmp([[return {name = "x", store_writes = {{pattern = "s.set", table = "1", value = 2}}}]])
      local dec, err = profiles.load_file(bad)
      assert_true(dec == nil, "a string position must be rejected")
      assert_match(tostring(err), "table")
      local both = write_tmp([[return {name = "x", store_writes = {{pattern = "s.set", table = 1, value = 2, row = 3}}}]])
      local dec2, err2 = profiles.load_file(both)
      assert_true(dec2 == nil, "value and row together must be rejected")
      assert_match(tostring(err2), "exactly one")
   end)

   it("honours a store a --rules profile declares", function()
      local rules = write_tmp([[return {name = "kv", store_writes = {{pattern = "kv.put", table = 1, column = 2, value = 3}},
         store_reads = {{pattern = "kv.get", table = 1, column = 2}}}]])
      local report = api.check_source('kv.put("cfg", "cmd", cgi["c"])\nos.execute(kv.get("cfg", "cmd"))\n',
         {std = "cgilua", rules = {rules}})
      assert_equal(count(report, "729"), 1, codes(report))
   end)
end)
