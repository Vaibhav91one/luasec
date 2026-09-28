-- Rule module: firmware.
--
-- A detector is a function(ctx). It calls ctx:emit(code, node, extra) for each
-- finding. See src/luasec/rules/context.lua for what a context offers.
--
-- Code this module owns: see docs/rules.md, and docs/firmware-stds.md for the
-- path and mode tables below.
local platform_api = require "luasec.registry.platform_api"
local taint_engine = require "luasec.engine.taint"

local M = {}

local detectors = {}

-- ---------------------------------------------------------------- path sets
--
-- Firmware paths are matched by anchored comparison only: whole-path equality, a
-- prefix compared at offset 1, or a test on the "/"-separated segments. No
-- entry is ever applied as a Lua pattern, so a path that merely contains the
-- text of an entry ("/tmp/etc/config/network", "/tmp/myshadowfile.txt") does not
-- match it, and no input can make these tests backtrack.
--
-- Every set is a table of these fields, all optional:
--
--   exact              the whole path equals this string
--   prefixes           the path begins with this string, compared at offset 1
--   segment_match      {count = <number of segments>,
--                       at = {{<1-based index>, "<literal>"}, ...}}
--                      the path is absolute, has exactly `count` segments, and
--                      the listed segments are the listed literals. Index 1 is
--                      the empty segment a leading "/" produces, so
--                      /proc/1/cmdline is count 4 with segment 4 "cmdline".
--   basename_prefixes  the last segment begins with one of these
--   basename_suffixes  the last segment ends with one of these
--
-- A vendor extends these tables here, or declares its own sets through
-- `--rules`, rather than editing any matching code.

-- Flash and kernel-state devices: a write here survives a reboot and can
-- replace the running image or a kernel tunable.
local FLASH_PATHS = {
   prefixes = {"/dev/mtd", "/dev/ubi", "/proc/sys/"},
   exact = {"/dev/nvram"},
}

-- Files a firmware service reads at boot, and the ones that decide what it
-- runs. A write here is persistence whether or not the data is attacker
-- controlled, so a constant write is reported too.
local FIRMWARE_CONFIG_PATHS = {
   prefixes = {"/etc/config/", "/etc/init.d/", "/etc/uci-defaults/"},
   exact = {"/etc/rc.local"},
}

-- Credentials and process state whose disclosure is the finding. "/etc/passwd"
-- is deliberately absent: it is world readable on a stock device, so reading it
-- is not the bug reading "/etc/shadow" is.
local SENSITIVE_READ_PATHS = {
   exact = {"/etc/shadow", "/proc/self/environ"},
   prefixes = {"/etc/ssl/private/"},
   -- /proc/<pid>/cmdline: the command line of any process on the device.
   segment_match = {count = 4, at = {{4, "cmdline"}}},
   basename_prefixes = {"id_rsa"},
   basename_suffixes = {".pem", ".key", ".p12"},
}

-- Paths a script has no business removing or renaming.
local PROTECTED_PATHS = {
   prefixes = {"/etc/init.d/", "/usr/bin/"},
   exact = {"/etc/rc.local"},
}

-- The UCI configuration file a config value lands in.
local UCI_CONFIG_DIR = "/etc/config/"

-- ------------------------------------------------------------ open() wrappers
--
-- The file APIs that take a path and a mode string, and which argument holds
-- each. A vendor with its own wrapper adds a line here; nothing else in this
-- module knows the name of a file API.
--
-- `profile` names the platform profile whose presence enables the API. It is
-- nil for an API every Lua has, and the name for one that only exists on that
-- platform's runtime.
local FILE_OPEN_APIS = {
   {path = "io.open", mode = 2},
   {path = "nixio.fs.open", mode = 2},
   {path = "file.open", mode = 2, profile = "espressif"},
}

-- ---------------------------------------------------------------- matching

-- Split a path on "/", keeping the empty leading segment so indexes count from
-- the root: "/etc/shadow" -> {"", "etc", "shadow"}. Uses plain find, so the
-- total work is proportional to the length of the path.
local function segments_of(path)
   local out = {}
   local from = 1
   while true do
      local at = path:find("/", from, true)
      if not at then
         out[#out + 1] = path:sub(from)
         return out
      end
      out[#out + 1] = path:sub(from, at - 1)
      from = at + 1
   end
end

-- Does `path` fall inside any of `sets`? Every test is O(#path) with a bounded
-- constant, so a long or adversarial path costs time proportional to its own
-- length and never more.
local function in_any_set(sets, path)
   local parts, basename

   for _, set in ipairs(sets) do
      for _, exact in ipairs(set.exact or {}) do
         if path == exact then return true end
      end
      for _, prefix in ipairs(set.prefixes or {}) do
         if path:sub(1, #prefix) == prefix then return true end
      end

      local rule = set.segment_match
      if rule and path:sub(1, 1) == "/" then
         if not parts then parts = segments_of(path) end
         if #parts == rule.count then
            local ok = true
            for _, pair in ipairs(rule.at or {}) do
               if parts[pair[1]] ~= pair[2] then
                  ok = false
                  break
               end
            end
            if ok then return true end
         end
      end

      if set.basename_prefixes or set.basename_suffixes then
         if not parts then parts = segments_of(path) end
         basename = parts[#parts]
         for _, text in ipairs(set.basename_prefixes or {}) do
            if basename:sub(1, #text) == text then return true end
         end
         for _, text in ipairs(set.basename_suffixes or {}) do
            if #basename >= #text and basename:sub(-#text) == text then
               return true
            end
         end
      end
   end

   return false
end

-- Is this expression built from a registered untrusted source?
--
-- The walk covers the expression and, for each local it names, that local's
-- definitions, visiting every local once. The step budget and the visited set
-- are what keep it linear on a file written to be expensive: a definition cycle
-- terminates, and a shape larger than the budget yields silence rather than a
-- guess, which costs the finding its `source` field and nothing else.
local TAINT_STEP_BUDGET = 2000

local function source_in(ctx, node, state, depth)
   if depth > 32 or type(node) ~= "table" then return nil end

   state.steps = state.steps + 1
   if state.steps > TAINT_STEP_BUDGET then return nil end

   if node.tag == "Call" or node.tag == "Invoke" then
      local callee_path = ctx:path_of(node[1])
      local source = callee_path and platform_api.match_source(callee_path)
      if source then return source.id end
   end

   if node.tag == "Id" and node.var then
      if state.seen[node.var] then return nil end
      state.seen[node.var] = true
      for _, value in ipairs(node.var.values or {}) do
         local found = source_in(ctx, value.node, state, depth + 1)
         if found then return found end
      end
      return nil
   end

   for index = 1, #node do
      local found = source_in(ctx, node[index], state, depth + 1)
      if found then return found end
   end

   return nil
end

local function source_of(ctx, node)
   return source_in(ctx, node, {steps = 0, seen = {}}, 0)
end

-- ---------------------------------------------------------------- helpers

-- Is a platform profile part of this analysis? Some APIs only exist on one
-- platform's runtime, so recognising them without the profile would report a
-- function named `file.open` in a program that has no such library.
local profiles = require "luasec.registry.profiles"
local profile_memo_ctx, profile_memo_active
local function profile_active(ctx, name)
   if not name then return true end
   if profile_memo_ctx ~= ctx then
      local active = {}
      local names = profiles.split(ctx.opts.std or "")
      if type(names) == "table" then
         for _, candidate in ipairs(names) do
            if type(candidate) == "string" then active[candidate] = true end
         end
      end
      profile_memo_ctx, profile_memo_active = ctx, active
   end
   return profile_memo_active[name] == true
end

-- "line:column" the way the taint engine keys its own findings, so the two
-- passes can be compared.
local function site_key(ctx, node)
   local line = node.line or 1
   return line .. ":" .. math.max(1, node.offset - (ctx.chstate.line_offsets[line] or 0) + 1)
end

-- True when the taint engine already reported `code` at this site. The engine
-- runs before the rule modules and does not hand its findings to the context,
-- so a detector that must not double-report re-derives them from the same
-- parsed program. The result is memoized per context and only computed once a
-- detector actually has a candidate statement to check, so a file with no
-- candidate never pays for the second pass.
local memo_ctx, memo_engine
local function engine_reported(ctx, node, code)
   if memo_ctx ~= ctx then
      local codes_by_site = {}
      for _, finding in ipairs(taint_engine.run(ctx.chstate, ctx.opts)) do
         local key = finding.line .. ":" .. finding.column
         codes_by_site[key] = codes_by_site[key] or {}
         codes_by_site[key][finding.code] = true
      end
      memo_ctx, memo_engine = ctx, codes_by_site
   end
   local at_site = memo_engine[site_key(ctx, node)]
   return at_site ~= nil and at_site[code] == true
end

-- ---------------------------------------------------------------- mode table
--
-- C's fopen mode string, which Lua passes through unchanged. A missing mode
-- means "r", so an `io.open(path)` with no mode is a read. The character
-- decides, not the position: "r+" reads and writes, "w+" truncates and writes.
--
--   read    the mode contains "r", or there is no mode
--   write   the mode contains "w" or "a", with or without "+"
--   truncate  the mode contains "w": an existing file loses its contents
local function read_mode(mode)
   if mode == nil then return true end
   return mode:find("r", 1, true) ~= nil
end

local function write_mode(mode)
   if mode == nil then return false end
   return mode:find("w", 1, true) ~= nil or mode:find("a", 1, true) ~= nil
end

local function truncating_mode(mode)
   if mode == nil then return false end
   return mode:find("w", 1, true) ~= nil
end

-- ---------------------------------------------------------------- 722

-- Which argument of a config write carries the value.
--
-- The platform profile says: `uci.set` is declared with a fourth argument,
-- `uci.sets` with a second. When the profile names an index the call does not
-- have -- the OpenWrt profile declares a fourth argument for `uci.add`, which
-- takes three -- the dataflow pass cannot see the write at all, so the last
-- argument is taken as the value, which is where firmware code puts the option
-- name. Returns nil when every candidate is a constant.
local function value_argument_index(ctx, sink, args)
   for _, index in ipairs(sink.arg or {}) do
      local arg = args[index]
      if arg and not ctx.is_constant(arg) then
         return index
      end
   end

   local last = args[#args]
   if #args > 0 and last and not ctx.is_constant(last) then
      for _, index in ipairs(sink.arg or {}) do
         if index > #args then return #args end
      end
   end

   return nil
end

-- The UCI path a config write lands in, as
-- `/etc/config/<config>.<section>.<option>`. The arguments between the config
-- name and the value are included when they are literals, which is what makes
-- the chain greppable. A value whose destination the script cannot resolve
-- still names the file, and says which part of it is computed.
local function uci_chain(ctx, args, value_index)
   local config = ctx.constant(args[1])
   if type(config) ~= "string" then
      return UCI_CONFIG_DIR .. "<computed config>", "<computed>"
   end
   -- Every config write the profiles declare is at most config, section, option,
   -- name, value, so three names can sit between the config and the value. The
   -- loop is over that fixed list rather than over an argument count the source
   -- never states, and an index past the value is not part of the chain.
   local chain = UCI_CONFIG_DIR .. config
   for _, index in ipairs({2, 3, 4}) do
      if index < value_index then
         local part = ctx.literal(args[index])
         if part then chain = chain .. "." .. part end
      end
   end
   return chain, config
end

-- Untrusted data written into UCI configuration, which a service may later
-- interpolate into a command. The config sinks are declared as data in
-- registry/stds/openwrt.lua and luci.lua, so this detector follows the profile:
-- with no OpenWrt or LuCI profile loaded there is no `uci` API to inject into.
local function detect_config_injection(ctx)
   ctx:each_call(function(node, path)
      if not path then return end
      local sink = platform_api.match_sink(path)
      if not sink or sink.kind ~= "config" then return end

      local args = ctx.args_of(node)
      local value_index = value_argument_index(ctx, sink, args)
      if not value_index then return end

      -- One statement, one finding. The taint engine reports a tainted config
      -- write as 709, and its generic dynamic-argument path reports a 722 with
      -- no destination. Both are this same statement, so this detector stands
      -- down rather than reporting it a second time; see docs/firmware-stds.md
      -- for the one-line change in the dataflow pass that hands 722 over.
      if engine_reported(ctx, node, "709") or engine_reported(ctx, node, "710")
            or engine_reported(ctx, node, "722") then
         return
      end

      local chain, config = uci_chain(ctx, args, value_index)
      ctx:emit("722", node, {
         name = path,
         sink = sink.pattern,
         chain = chain,
         uci_config = config,
      })
   end)
end

detectors[#detectors + 1] = detect_config_injection

-- ---------------------------------------------------------------- 723

-- Does this call open a file, and which nodes hold the path and the mode?
local function open_call(ctx, node, path)
   for _, api in ipairs(FILE_OPEN_APIS) do
      if path == api.path and profile_active(ctx, api.profile) then
         local args = ctx.args_of(node)
         return api, args[1], ctx.literal(args[api.mode])
      end
   end
   return nil
end

-- A read of a credential file or of another process's state. The path has to be
-- a literal: a path the script computes is a different finding, and one we
-- cannot resolve. "/etc/passwd" is not here, because it is world readable on a
-- stock device and reading it is not the bug reading "/etc/shadow" is.
local function detect_sensitive_read(ctx)
   ctx:each_call(function(node, path)
      if not path then return end
      local api, path_node, mode = open_call(ctx, node, path)
      if not api then return end
      local file_path = ctx.literal(path_node)
      if not file_path then return end
      if not read_mode(mode) then return end
      if not in_any_set({SENSITIVE_READ_PATHS}, file_path) then return end

      ctx:emit("723", node, {name = path, path = file_path})
   end)
end

detectors[#detectors + 1] = detect_sensitive_read

-- ---------------------------------------------------------------- 721

-- The literal run at the start of a path expression, which is what decides
-- whether a computed path is still a flash path. `"/dev/mtd" .. n` starts with
-- "/dev/mtd"; `n .. "/dev/mtd"` starts with nothing we can trust, so it is not
-- matched.
--
-- A local is followed to its definition, and only when every definition in
-- scope agrees on the leading run: a variable that is sometimes /tmp/scratch
-- and sometimes /etc/config/network decides nothing. Definitions are not
-- flow-sensitive here, so a variable that only sometimes carries a firmware
-- path is not reported; the visited set keeps a definition cycle terminating.
local function leading_literal(ctx, node, seen, depth)
   depth = depth or 0
   if depth > 16 or type(node) ~= "table" then return nil end

   if node.tag == "String" then return node[1] end
   if node.tag == "Paren" then return leading_literal(ctx, node[1], seen, depth + 1) end
   if node.tag == "Op" and node[1] == "concat" then
      local left = leading_literal(ctx, node[2], seen, depth + 1)
      if left == nil then return nil end
      local right = ctx.literal(node[3])
      if right == nil then return left end
      return left .. right
   end

   if node.tag == "Id" and node.var and not seen[node.var] then
      seen[node.var] = true
      local agreed
      for _, value in ipairs(node.var.values or {}) do
         local found = leading_literal(ctx, value.node, seen, depth + 1)
         if agreed == nil then
            agreed = found
         elseif found == nil or found ~= agreed then
            return nil
         end
      end
      return agreed
   end

   return nil
end

local function path_prefix(ctx, node)
   return leading_literal(ctx, node, {}, 0)
end

-- A write to a flash device or to a file a boot-time service reads. A constant
-- write is the finding: it is persistence across a reboot whoever chose the
-- contents, and a value the analyzer cannot trace is still a value someone
-- chose. When the path itself is computed from a request the finding says so.
--
-- A mode the source does not state is reported at low confidence: the path is
-- firmware state either way, and we cannot claim a write we cannot see, but
-- neither can we call the file safe.
local function detect_firmware_write(ctx)
   ctx:each_call(function(node, path)
      if not path then return end
      local api, path_node, mode = open_call(ctx, node, path)
      if not api then return end

      local mode_known = mode ~= nil
      if mode_known and not write_mode(mode) then return end

      local literal = ctx.literal(path_node)
      local prefix = literal or path_prefix(ctx, path_node)
      if not prefix then return end
      if not in_any_set({FLASH_PATHS, FIRMWARE_CONFIG_PATHS}, prefix) then return end

      -- One statement, one finding: under the espressif profile `file.open` is
      -- also declared as a 721 sink, and the dataflow pass has already reported
      -- that statement.
      if engine_reported(ctx, node, "721") then return end

      local extra = {name = path, sink = path, path = prefix}
      if not mode_known then
         extra.confidence = "low"
         extra.mode = "<computed>"
      elseif literal then
         extra.confidence = "high"
      else
         extra.path = prefix .. "<computed>"
         extra.confidence = "medium"
         local source = source_of(ctx, path_node)
         if source then extra.source = source end
      end
      ctx:emit("721", node, extra)
   end)
end

detectors[#detectors + 1] = detect_firmware_write

-- ---------------------------------------------------------------- 725

-- The dotted name an expression has: a local, a global, or a chain of field
-- accesses rooted in either. `package.cpath[1]` stops at "package.cpath": the
-- key is a variable, but the table it indexes is still named, and that is the
-- part worth a finding.
--
-- With `globals_only` a name rooted in a local is nil, because a field on a
-- local table is not a global this script is manipulating.
local function dotted_name(node, globals_only, depth)
   depth = depth or 0
   if depth > 16 or type(node) ~= "table" then return nil end

   if node.tag == "Id" then
      if globals_only and node.var then return nil end
      return node[1]
   end
   if node.tag == "Index" then
      local base = dotted_name(node[1], globals_only, depth + 1)
      if not base then return nil end
      local key = node[2]
      if type(key) == "table" and key.tag == "String" then
         return base .. "." .. key[1]
      end
      return base
   end

   return nil
end

-- Globals whose rebinding changes what some other chunk sees. Only the binding
-- itself counts: `_G = {}` and `package.loaded = {}` replace the table, while
-- `_G.own = 1` and `package.loaded["mymod"] = M` are how every Lua program
-- declares a global and publishes a module.
local REBOUND_GLOBALS = {
   ["_G"] = true,
   ["_ENV"] = true,
   ["package.loaded"] = true,
}

-- Globals whose contents decide what code the interpreter will load next. Here a
-- field write counts, because `package.path = ...` and `package.cpath[1] = ...`
-- are the two idioms and the second has no other spelling.
local MUTATED_LOAD_PATHS = {
   ["package.path"] = true,
   ["package.cpath"] = true,
}

-- Calls that hand a chunk a different environment. `debug.setfenv` is the 5.1
-- spelling of `setfenv` and reaches the same sandbox.
local ENVIRONMENT_CALLS = {
   setfenv = true,
   ["debug.setfenv"] = true,
}

local function detect_environment_change(ctx)
   ctx:each_call(function(node, path)
      if not path then return end
      local args = ctx.args_of(node)

      if ENVIRONMENT_CALLS[path] then
         ctx:emit("725", node, {name = path})
         return
      end

      if path == "debug.setmetatable" and dotted_name(args[1], true) == "_G" then
         ctx:emit("725", node, {name = path})
         return
      end
   end)

   ctx:each_node(function(node)
      if node.tag ~= "Set" and node.tag ~= "OpSet" then return end
      local targets = node[1]
      if type(targets) ~= "table" then return end
      for index = 1, #targets do
         local name = dotted_name(targets[index], true)
         if REBOUND_GLOBALS[name] or MUTATED_LOAD_PATHS[name] then
            ctx:emit("725", targets[index], {name = name})
         end
      end
   end)
end

detectors[#detectors + 1] = detect_environment_change

-- ---------------------------------------------------------------- 726

-- Every path this script opens for writing, with the offset of the earliest such
-- open. One pass, memoized per context, so the self-modifying check costs one
-- extra walk of the file rather than one walk per candidate statement.
local written_memo_ctx, written_memo
local function written_paths(ctx)
   if written_memo_ctx == ctx then return written_memo end

   local earliest = {}
   ctx:each_call(function(node, path)
      if not path then return end
      local api, path_node, mode = open_call(ctx, node, path)
      if not api or not write_mode(mode) then return end
      local file_path = path_prefix(ctx, path_node)
      if not file_path then return end
      if earliest[file_path] == nil or node.offset < earliest[file_path] then
         earliest[file_path] = node.offset
      end
   end)

   written_memo_ctx, written_memo = ctx, earliest
   return earliest
end

-- A single open cannot be both the earlier write and the later truncation, so
-- comparing offsets is enough to say "the script wrote this file first".
local function written_earlier(ctx, node, file_path)
   local first = written_paths(ctx)[file_path]
   return first ~= nil and first < node.offset
end

-- Removing a firmware path, renaming one away, or truncating a file this script
-- had already written. Everything else the script does to its own scratch files
-- is its own business.
--
-- `os.rename` is reported on the path it destroys, not on the destination: a
-- rename that takes /etc/rc.local away is the finding, and the name of the
-- finding is the API the operator has to look for in the source.
local DESTRUCTIVE_APIS = {
   ["os.remove"] = {paths = {1}},
   ["os.rename"] = {paths = {1}},
}

local function detect_destructive(ctx)
   ctx:each_call(function(node, path)
      if not path then return end
      local args = ctx.args_of(node)

      local destructive = DESTRUCTIVE_APIS[path]
      if destructive then
         for _, index in ipairs(destructive.paths) do
            local file_path = path_prefix(ctx, args[index])
            if file_path and in_any_set({PROTECTED_PATHS, FIRMWARE_CONFIG_PATHS}, file_path) then
               ctx:emit("726", node, {name = path, path = file_path})
            end
         end
         return
      end

      local api, path_node, mode = open_call(ctx, node, path)
      if not api or not truncating_mode(mode) then return end
      local file_path = path_prefix(ctx, path_node)
      if not file_path then return end
      if not in_any_set({PROTECTED_PATHS, FIRMWARE_CONFIG_PATHS}, file_path) then return end
      if not written_earlier(ctx, node, file_path) then return end
      ctx:emit("726", node, {name = path, path = file_path})
   end)
end

detectors[#detectors + 1] = detect_destructive

-- ---------------------------------------------------------------- 727
--
-- A loop that makes a string or a table bigger with no ceiling the source
-- states. A numeric for whose limit is a literal is the one shape that cannot
-- outgrow the device, and a measured run over luasec's own source showed that
-- "not a literal" is nowhere near enough: `for k, v in pairs(t) do
-- out[#out+1] = v end` is the most common line in the language, and a count
-- nobody wrote down is not the same as a count nobody can see.
--
-- So the question is not "is the limit a literal" but "can the source see a
-- ceiling". Four ways it can, and the rest are this finding:
--
--   * a numeric for whose limit and step are both constant-foldable, or whose
--     limit is a length: the loop runs once per element of something
--   * a generic for over a finite iterator: pairs, ipairs, next, a gmatch, a
--     lines() call. These yield one turn per element, match or line
--   * a while or repeat whose condition compares against a length
--   * any loop whose own body returns or breaks before it can come back around,
--     which is how `while true do ... return out end` is spelled
--
-- A doubling is the exception that needs no unbounded loop: `s = s .. s` costs
-- 2^n whatever n is, and 32 turns of it is 4 GB. Inside a bounded loop it is
-- still the finding.

-- The body of a loop node, or nil when the node is not a loop. A for's block is
-- its last element; a repeat's is its first, because its condition comes last.
local function loop_body(node)
   local tag = node.tag
   if tag == "Fornum" or tag == "Forin" or tag == "While" then
      return node[#node]
   elseif tag == "Repeat" then
      return node[1]
   end
   return nil
end

-- Does this expression mention a length? `#t` is the number of turns a loop
-- over t can take, so a limit or a bound that mentions one is a ceiling.
--
-- A shape deeper than the depth cap answers yes, not no. Every other bounded
-- walk in this module answers "no finding" when it runs out of budget, and this
-- one must too: an expression nobody can read is not evidence of a ceiling, but
-- it is certainly not evidence of an unbounded loop either, and a silent miss
-- is the cheaper mistake to make than a finding on a shape we do not
-- understand.
local function mentions_length(node, depth)
   depth = depth or 0
   if depth > 16 then return true end
   if type(node) ~= "table" then return false end
   if node.tag == "Op" and node[1] == "len" then return true end
   for index = 1, #node do
      if mentions_length(node[index], depth + 1) then return true end
   end
   return false
end

-- Iterators whose length is a property of the program: a container's size, or
-- the number of matches or lines in a string. Anything else may yield forever,
-- and an unknown iterator is the case worth reporting.
local FINITE_ITERATORS = {
   pairs = true,
   ipairs = true,
   next = true,
   gmatch = true,
   lines = true,
}

local function finite_iterator(ctx, exprs)
   if type(exprs) ~= "table" or #exprs == 0 then return false end
   local first = exprs[1]
   if type(first) ~= "table" then return false end

   if first.tag == "Call" then
      local callee = first[1]
      if type(callee) == "table" and callee.tag == "Index" then
         -- string.gmatch(x, p) and the other library-qualified forms
         return FINITE_ITERATORS[callee[2] and callee[2][1]] == true
      end
      return FINITE_ITERATORS[ctx:path_of(callee)] == true
   end

   -- pipe:lines() and the other method forms
   if first.tag == "Invoke" then
      return FINITE_ITERATORS[first[2] and first[2][1]] == true
   end

   return false
end

-- `s = s .. x` grows a string, `t[#t + 1] = x` and `table.insert(t, x)` grow a
-- table, and `s = s .. s` grows a string at twice the rate. The third is
-- reported on its own because its cost is exponential rather than linear.
local GROWTH_RANK = {string = 1, double = 2}

-- Does `s = <value>` make `s` bigger, and how fast?
--
-- Concatenation nests to the left, so the target is somewhere on the left spine
-- of the `..` chain. The operand appended at that point decides the rate: a
-- fixed operand is a linear growth, and the target itself is a doubling.
-- `s = s .. "x"`, `s = s .. x` and `s = s .. s .. "x"` all read here.
local function concat_growth(target, value)
   local name = dotted_name(target, false)
   if name == nil then return nil end

   local node = value
   while type(node) == "table" and node.tag == "Op" and node[1] == "concat" do
      if dotted_name(node[2], false) == name then
         return dotted_name(node[3], false) == name and "double" or "string"
      end
      node = node[2]
   end

   return nil
end

local function better_growth(current, candidate)
   if not candidate then return current end
   if not current then return candidate end
   if GROWTH_RANK[candidate] > GROWTH_RANK[current] then return candidate end
   return current
end

local statement_growth, statement_exits, block_check

-- Walk a block, applying `check` to each statement at its own nesting level.
-- Both checks take the context first, so one walk serves both; whether a check
-- descends into a nested loop's body is its own business, because a growth
-- counts however deep it is while a return or break belongs only to the loop
-- that encloses it.
block_check = function(ctx, block, depth, check)
   if type(block) ~= "table" or depth > 24 then return nil end
   if block.tag then return check(ctx, block, depth) end
   for index = 1, #block do
      local statement = block[index]
      if type(statement) == "table" and statement.tag then
         local found = check(ctx, statement, depth + 1)
         if found then return found end
      end
   end
   return nil
end

statement_growth = function(ctx, statement, depth)
   depth = depth or 0
   if type(statement) ~= "table" or depth > 24 then return nil end

   local tag = statement.tag
   if tag == "Set" or tag == "OpSet" then
      local targets, values = statement[1], statement[2]
      if type(targets) ~= "table" or type(values) ~= "table" then return nil end
      local found
      for index = 1, #targets do
         local target, value = targets[index], values[index]
         if type(value) == "table" and value.tag == "Op" and value[1] == "concat" then
            found = better_growth(found, concat_growth(target, value))
         elseif type(target) == "table" and target.tag == "Index" then
            local key = target[2]
            if type(key) == "table" and key.tag == "Op" and key[1] == "add"
                  and type(key[3]) == "table" and key[3].tag == "Number"
                  and type(key[2]) == "table" and key[2].tag == "Op" and key[2][1] == "len"
                  and dotted_name(target[1], false) == dotted_name(key[2][2], false) then
               found = better_growth(found, "table")
            end
         end
      end
      return found
   end

   if tag == "Call" or tag == "Invoke" then
      if ctx:path_of(statement[1]) == "table.insert" then return "table" end
      return nil
   end

   if tag == "Do" then
      return block_check(ctx, statement[1], depth + 1, statement_growth)
   end
   local body = loop_body(statement)
   if body then
      return block_check(ctx, body, depth + 1, statement_growth)
   end
   if tag == "If" then
      -- {condition, block, condition, block, ..., [else block]}
      for index = 2, #statement, 2 do
         local found = block_check(ctx, statement[index], depth + 1, statement_growth)
         if found then return found end
      end
      if #statement % 2 == 1 then
         return block_check(ctx, statement[#statement], depth + 1, statement_growth)
      end
      return nil
   end

   return nil
end

-- ctx is in the signature only so one walk serves both statement checks.
statement_exits = function(ctx, statement, depth)
   depth = depth or 0
   if type(statement) ~= "table" or depth > 24 then return nil end

   if statement.tag == "Return" or statement.tag == "Break" then return true end
   -- A return or break inside a nested loop belongs to that loop, not this one.
   if loop_body(statement) then return nil end
   if statement.tag == "Do" then
      return block_check(ctx, statement[1], depth + 1, statement_exits)
   end
   if statement.tag == "If" then
      for index = 2, #statement, 2 do
         if block_check(ctx, statement[index], depth + 1, statement_exits) then return true end
      end
      if #statement % 2 == 1 and block_check(ctx, statement[#statement], depth + 1, statement_exits) then
         return true
      end
   end

   return nil
end

-- Can the source see a ceiling on this loop?
local function loop_is_bounded(ctx, node)
   if block_check(ctx, loop_body(node), 0, statement_exits) then return true end

   local tag = node.tag
   if tag == "Forin" then
      return finite_iterator(ctx, node[2])
   end
   if tag == "While" then
      return mentions_length(node[1])
   end
   if tag == "Repeat" then
      local condition = node[2]
      -- `until false` never ends, whatever the body does.
      if type(condition) == "table" and condition.tag == "False" then return false end
      return mentions_length(condition)
   end

   -- A numeric for is {var, init, limit, block} with no step and
   -- {var, init, limit, step, block} with one, so a fifth element is what says
   -- the step was written out.
   if #node >= 5 and not ctx.is_constant(node[4]) and not mentions_length(node[4]) then
      return false
   end
   return ctx.is_constant(node[3]) or mentions_length(node[3])
end

local function detect_unbounded_growth(ctx)
   -- `string.rep(unit, n)` allocates unit * n bytes from a count nobody wrote
   -- down. Only a count carrying untrusted data is the finding: a count the
   -- script computed from its own recursion depth is a design, not an attack.
   ctx:each_call(function(node, path)
      if path ~= "string.rep" then return end
      local count = ctx.args_of(node)[2]
      if not count or ctx.is_constant(count) then return end
      if not source_of(ctx, count) then return end
      ctx:emit("727", node, {name = path, confidence = "medium"})
   end)

   ctx:each_node(function(node)
      local body = loop_body(node)
      if not body then return end
      local growth = block_check(ctx, body, 0, statement_growth)
      if not growth then return end
      if growth == "double" then
         ctx:emit("727", node, {name = node.tag})
         return
      end
      -- A string accumulator is the shape that exhausts memory: the turn count
      -- multiplies a size the script chose. A table is bounded by the data that
      -- fills it - a script collecting N items holds N items - so a table is
      -- only this finding when even the turn count has no ceiling in the source,
      -- which rules out the numeric for a programmer writes by counting.
      if growth == "table" and node.tag == "Fornum" then return end
      if loop_is_bounded(ctx, node) then return end
      ctx:emit("727", node, {name = node.tag})
   end)
end

detectors[#detectors + 1] = detect_unbounded_growth

-- ---------------------------------------------------------------- 728

-- Library functions whose second argument is a pattern. A caller who chooses
-- the pattern chooses the captures and the repetition counts the matcher walks,
-- which is a denial of service rather than a search, so a pattern the source
-- does not state is the finding.
--
-- `string.find(s, p, init, plain)` with `plain` true does not match a pattern at
-- all, so that call is not one of these.
local PATTERN_APIS = {
   ["string.find"] = {pattern = 2, plain = 4},
   ["string.match"] = {pattern = 2},
   ["string.gmatch"] = {pattern = 2},
   ["string.gsub"] = {pattern = 2},
   ["ngx.re.find"] = {pattern = 2},
   ["ngx.re.gsub"] = {pattern = 2},
}

local function detect_dynamic_pattern(ctx)
   ctx:each_call(function(node, path)
      if not path then return end
      local api = PATTERN_APIS[path]
      if not api then return end

      local args = ctx.args_of(node)
      if api.plain then
         local plain = args[api.plain]
         if type(plain) == "table" and plain.tag == "True" then return end
      end

      local pattern = args[api.pattern]
      if not pattern or ctx.is_constant(pattern) then return end

      local source = source_of(ctx, pattern)
      ctx:emit("728", node, {
         name = path,
         sink = path,
         source = source,
         confidence = source and "high" or "medium",
      })
   end)
end

detectors[#detectors + 1] = detect_dynamic_pattern

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

return M

