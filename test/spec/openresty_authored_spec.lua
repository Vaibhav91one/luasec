-- An AUTHORED nginx.conf, measured (#296). `lua-nginx-module` ships no handler of its own once the
-- Test::Nginx `.t` files are excluded (#288), and a deployed nginx.conf is not something that can be
-- cloned, so one is written here: fifteen `location` blocks whose `content_by_lua_block` bodies are
-- typical request handlers, each carrying the author's intent on its first line (`-- expect: 730`, or
-- `-- expect: none` for a handler that is safe).
--
-- WHAT THIS MEASURES: whether lua-doctor reports what the author meant to be reported, on handlers the
-- author chose. WHAT IT DOES NOT: real-world recall or precision. The author wrote both the handlers
-- and the intent, so it can only show that a known idiom is, or is not, handled; it cannot show the
-- rate at which real deployments differ from the author's imagination. docs/precision.md says the same.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luadoctor.api"

local CONF = "test/fixtures/openresty-authored/nginx.conf"

-- Pull every `location ... { content_by_lua_block { ... } }` body out of an nginx.conf. Braces inside
-- a Lua string are not block braces, so quotes are skipped while the block is balanced. Long strings
-- and comments containing braces are not handled: the authored file has none, and the spec below
-- pins the extraction by count so a block that breaks it is noticed.
local function blocks_of(conf)
   local blocks = {}
   local pos = 1
   while true do
      local s, e = conf:find("location%s*=?%s*[^%s{]+%s*{%s*content_by_lua_block%s*{", pos)
      if not s then break end
      local name = conf:match("location%s*=?%s*([^%s{]+)", s)
      local depth, i, quote = 1, e + 1, nil
      while depth > 0 do
         local c = conf:sub(i, i)
         assert(c ~= "", "unbalanced content_by_lua_block for " .. name)
         if quote then
            if c == "\\" then i = i + 1 elseif c == quote then quote = nil end
         elseif c == '"' or c == "'" then
            quote = c
         elseif c == "{" then
            depth = depth + 1
         elseif c == "}" then
            depth = depth - 1
         end
         i = i + 1
      end
      blocks[#blocks + 1] = {name = name, body = conf:sub(e + 1, i - 2)}
      pos = i
   end
   return blocks
end

local function read(path)
   local handle = assert(io.open(path, "r"))
   local text = handle:read("*a")
   handle:close()
   return text
end

local function reported(body)
   local out = {}
   for _, finding in ipairs(api.check_source(body, {std = "openresty"})) do
      out[#out + 1] = finding.code .. "/" .. finding.confidence
   end
   table.sort(out)
   return table.concat(out, ",")
end

local function codes_only(reported_text)
   local out = {}
   for item in reported_text:gmatch("[^,]+") do out[#out + 1] = item:match("^(%d+)/") end
   table.sort(out)
   return #out == 0 and "none" or table.concat(out, ",")
end

-- What lua-doctor reports today for each handler, pinned. A change here is a change in behaviour on a
-- handler somebody wrote on purpose, so it has to be made on purpose.
local PINNED = {
   ["/healthz"] = "", ["/go"] = "730/certain", ["/next"] = "", ["/handoff"] = "709/medium",
   ["/fallback"] = "", ["/forward-host"] = "730/certain", ["/cache-key"] = "730/medium",
   ["/served-by"] = "", ["/proxy"] = "", ["/ping"] = "709/medium", ["/ping-checked"] = "709/medium",
   ["/kill"] = "701/low", ["/dns"] = "709/certain", ["/run"] = "709/high", ["/find"] = "728/high",
}

-- Every handler where what lua-doctor reports differs from the author's intent, and why. A mismatch that
-- is not listed here fails the spec, so a gap cannot be added by accident or hidden by a pin.
local GAPS = {
   ["/proxy"] = "missed: the registry models only the OPTIONS table of ngx.location.capture " ..
      "(CVE-2020-11724 request framing, argument 2); a tainted subrequest URI in argument 1 is " ..
      "deliberately not a sink (openresty.lua: arg = {2})",
   ["/ping-checked"] = "false positive: the host is validated with string.match before os.execute; " ..
      "lua-doctor has no notion of a validating guard, so the flow is reported at 709/medium",
   ["/kill"] = "false positive at low confidence: tonumber + %d makes the value safe, but a non-constant " ..
      "argument to os.execute is still a 701 shape finding (low)",
}

describe("an authored OpenResty nginx.conf (#296)", function()
   local blocks = blocks_of(read(CONF))

   it("extracts every content_by_lua_block, including one with braces in a string", function()
      assert_equal(#blocks, 15, "the authored file declares fifteen handlers")
      local tricky = blocks_of('location = /x { content_by_lua_block { local s = "}{" ngx.say(s) } }')
      assert_equal(#tricky, 1)
      assert_equal(tricky[1].body:find('ngx.say(s)', 1, true) ~= nil, true,
         "a brace inside a Lua string closed the block early")
   end)

   it("pins what lua-doctor reports for every handler", function()
      for _, block in ipairs(blocks) do
         assert_true(PINNED[block.name] ~= nil, block.name .. " has no pinned result")
         assert_equal(reported(block.body), PINNED[block.name],
            block.name .. ": what lua-doctor reports changed")
      end
   end)

   it("names every handler where the report differs from the author's intent, and only those", function()
      for _, block in ipairs(blocks) do
         local intent = block.body:match("%-%- expect: ([%w, ]+)")
         assert_true(intent ~= nil, block.name .. " has no `-- expect:` line")
         intent = intent:gsub("%s", "")
         local matches = intent == codes_only(reported(block.body))
         if matches then
            assert_equal(GAPS[block.name], nil, block.name .. " matches its intent but is listed as a gap")
         else
            assert_true(GAPS[block.name] ~= nil, block.name .. ": reported " .. codes_only(reported(block.body))
               .. " but the author intended " .. intent .. ", and it is not a documented gap")
         end
      end
   end)

   it("states the same totals as docs/precision.md", function()
      local tp, tn, miss, fp = 0, 0, 0, 0
      for _, block in ipairs(blocks) do
         local intent = block.body:match("%-%- expect: ([%w, ]+)"):gsub("%s", "")
         local got = codes_only(reported(block.body))
         if intent == got then
            if intent == "none" then tn = tn + 1 else tp = tp + 1 end
         elseif intent == "none" then
            fp = fp + 1
         else
            miss = miss + 1
         end
      end
      assert_equal(tp .. "/" .. tn .. "/" .. miss .. "/" .. fp, "8/4/1/2")
      local doc = read("docs/precision.md")
      local sentence = "8 reported as intended, 4 silent as intended, 1 missed, 2 reported although safe"
      assert_true(doc:find(sentence, 1, true) ~= nil,
         "docs/precision.md must state: " .. sentence)
   end)
end)
