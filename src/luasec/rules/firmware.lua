-- Rule module: firmware.
--
-- A detector is a function(ctx). It calls ctx:emit(code, node, extra) for each
-- finding. See src/luasec/rules/context.lua for what a context offers.
--
-- Code this module owns: see docs/rules.md, and docs/firmware-stds.md for the
-- path and mode tables below.
local platform_api = require "luasec.registry.platform_api"
local callgraph = require "luasec.engine.callgraph"
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
--
-- `setfenv` on its own is NOT the finding. In LuCI it is the everyday way to
-- instantiate a form object: `setfenv(form, getfenv(1))(m, wdg)`. Measured over
-- 566 real firmware files, flagging every `setfenv` fired on 22 files and every
-- one was that idiom. What matters is handing a *caller* a new environment, or
-- handing a chunk an environment that still holds the dangerous libraries.
local ENVIRONMENT_CALLS = {
   setfenv = true,
   ["debug.setfenv"] = true,
}

-- Libraries that make an environment an escape rather than a namespace.
local CAPABILITY_FIELDS = {
   io = true, os = true, package = true, loadstring = true, load = true,
   dofile = true, loadfile = true, require = true, debug = true, ffi = true,
   ["_G"] = true, ["_VERSION"] = false,
}

-- Does this table literal hand an environment a library that can execute or read
-- the filesystem? A computed table is not proven either way, so only literals
-- count.
local function grants_capability(ctx, node)
   if type(node) ~= "table" or node.tag ~= "Table" then return false end
   for _, pair_node in ipairs(node) do
      if pair_node.tag == "Pair" and pair_node[1] and pair_node[1].tag == "String" then
         if CAPABILITY_FIELDS[pair_node[1][1]] then return true end
      end
   end
   return false
end

local function detect_environment_change(ctx)
   ctx:each_call(function(node, path)
      if not path then return end
      local args = ctx.args_of(node)

      if ENVIRONMENT_CALLS[path] then
         -- setfenv(1, env) rewrites the *caller's* environment: that is an
         -- escape. setfenv(chunk, env) is a namespace, unless the environment
         -- hands back io, os, package, loadstring and the rest.
         if ctx.constant(args[1]) == 1 then
            ctx:emit("725", node, {name = path, reason = "caller environment replaced"})
            return
         end
         if grants_capability(ctx, args[2]) then
            ctx:emit("725", node, {name = path, reason = "environment keeps a dangerous library"})
         end
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
      -- Only a string accumulator is this finding. A table is bounded by the
      -- data that fills it: a script collecting N items holds N items, and
      -- collecting them is the idiom, not the bug. Measured against 589 real
      -- firmware Lua files, reporting table growth flagged a quarter of them and
      -- every one of those was a collector table.
      if growth == "table" then return end
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

-- ---------------------------------------------------------------- 724
--
-- A function holding an execution sink that is registered as a callable entry
-- point. On a router `os.execute` is not the finding; `os.execute` that someone
-- on the network can reach with arguments of their choosing is. 724 names the
-- exposure mechanism, which is the one part no single file can prove: 708 says
-- the input lives somewhere we cannot see, and this says who can call it.
--
-- The registration is what makes a function a handler. A helper with a sink in a
-- table of helpers is 708's business; a function written onto an object the
-- device hands to something else is this rule's. That is the whole difference
-- between the two codes, and it is why both can stand on one function: 708 is
-- about the argument, 724 is about the caller.

-- Calls that hand back a ubus object, so a method map written onto the result is
-- an RPC surface. A vendor binding of their own adds a line; nothing else in
-- this module knows the name of an RPC API.
--
-- These are OpenWrt's bindings as documented rather than as measured: the
-- firmware corpora available to this project hold no rpcd plugin, so there was
-- no real spelling here to count before naming any. That is why the table is
-- short, and why a false positive from it would be this module's own.
local UBUS_OBJECT_CALLS = {
   ["ubus.add"] = true,
   ["ubus.add_object"] = true,
   ["ubus.object"] = true,
   ["rpcd.modplug.init"] = true,
}

-- The field names a receiver of a returned object calls, which is what makes a
-- field on it a handler rather than a helper.
--
-- Two lists, and both are the receiving side's vocabulary rather than ours. The
-- names are the hooks LuCI's CBI framework calls on a map it was handed
-- (cbi.lua's `_run_hooks` list), plus the names a plugin interface uses for the
-- operation that does the work. The prefixes are the two spellings of a handler
-- nobody has a fixed name for.
local HANDLER_NAMES = {
   apply = true,
   commit = true,
   write = true,
   exec = true,
   run = true,
   execute = true,
   on_parse = true,
   on_save = true,
   on_before_save = true,
   on_after_save = true,
   on_commit = true,
   on_before_commit = true,
   on_after_commit = true,
   on_apply = true,
   on_before_apply = true,
   on_after_apply = true,
}

local HANDLER_PREFIXES = {"handle", "handler"}

local function is_handler_name(key)
   if HANDLER_NAMES[key] then return true end
   for _, prefix in ipairs(HANDLER_PREFIXES) do
      if key:sub(1, #prefix) == prefix then return true end
   end
   return false
end

-- Is this a call that executes? `exec` and `dyncode` are the execution kinds the
-- registry declares, whichever platform declares them, and 707 is the FFI escape
-- hatch, which executes whatever the C library beside it is asked to execute. A
-- platform profile adds its own exec sink and it counts here without this module
-- knowing the name.
--
-- The two are told apart because a handler that both declares a C prototype and
-- calls it is reported against the call: `ffi.cdef` is how the escape is set up,
-- `ffi.C.system` is the execution.
local function execution_sink(path)
   local sink = platform_api.match_sink(path)
   if sink and (sink.kind == "exec" or sink.kind == "dyncode") then return "exec", sink end
   local shape = platform_api.match_shape(path)
   if shape and shape.code == "707" then return "shape", shape end
   return nil
end

-- The first execution sink inside a function, as the dataflow pass's own view of
-- that function sees it: the lines the function owns, so a sink in a nested
-- closure belongs to the closure and a sink in a wrapper belongs to the wrapper.
-- This is the question 708 asks of the same function, asked from the linearized
-- program rather than from a second walk of the AST, so a file with thousands of
-- one-line handlers stays linear.
--
-- A sink whose flow is already proven is not this rule's: 709 is critical, names
-- the source and carries the trace, and the operator acts on it. 724 would add
-- only that the function is registered, which the operator reads in the file. So
-- a handler whose every sink is proven is silent here, and the walk carries on
-- past a proven sink to an unproven one rather than stopping at it. This is the
-- decision the exposed-sink pass already makes about 708.
--
-- A file too large for the linearizer to attribute a function to a line has no
-- lines to ask, and the question is then answered by walking the function's own
-- body instead. That answer is coarser in two ways and neither costs precision:
-- a callee bound to anything but a required module resolves to nothing, so such a
-- call is silent rather than misattributed, and a nested closure's sink counts
-- for the handler that encloses it, which is true of anything the closure's own
-- registration would have said.
local function sink_in_body(ctx, function_node)
   local found, escape
   local function visit(node, depth)
      if found or depth > 200 or type(node) ~= "table" then return end
      if node.tag == "Call" or node.tag == "Invoke" then
         local path = call_path(ctx, node)
         if path then
            local kind = execution_sink(path)
            if kind and not engine_reported(ctx, node, "709")
                  and not engine_reported(ctx, node, "710") then
               if kind == "exec" then
                  found = {path = path, node = node}
                  return
               end
               escape = escape or {path = path, node = node}
            end
         end
      end
      for index = 1, #node do
         local child = node[index]
         if type(child) == "table" then
            if child.tag then
               visit(child, depth + 1)
            else
               for _, sub in ipairs(child) do
                  if type(sub) == "table" and sub.tag then visit(sub, depth + 1) end
               end
            end
         end
      end
   end

   visit(function_node, 0)
   return found, escape
end

-- Memoized per context, and the memo is what keeps a function registered twice
-- from costing two walks.
local sink_memo_ctx, sink_memo
local function first_sink(ctx, function_node, state)
   if sink_memo_ctx == ctx then
      local memoized = sink_memo[function_node]
      if memoized ~= nil then return memoized end
   else
      sink_memo_ctx, sink_memo = ctx, {}
   end

   local found, escape
   local lines = callgraph.index_lines(ctx.chstate)[function_node]
   if not lines then
      found, escape = sink_in_body(ctx, function_node)
   end
   for _, line in ipairs(lines or {}) do
      for _, item in ipairs(line.items) do
         if item.tag == "Eval" then
            local node = item.node
            if node and (node.tag == "Call" or node.tag == "Invoke") then
               local callee = node.tag == "Invoke" and node or node[1]
               local path = callee and taint_engine.callee_path(callee, item, state) or nil
               if path then
                  local kind = execution_sink(path)
                  -- A sink whose flow is already proven is 709's finding; the
                  -- walk carries on to an unproven one rather than stopping.
                  if kind and not engine_reported(ctx, node, "709")
                        and not engine_reported(ctx, node, "710") then
                     local hit = {path = path, node = node}
                     if kind == "exec" then
                        found = hit
                        break
                     end
                     escape = escape or hit
                  end
               end
            end
         end
      end
      if found then break end
   end

   found = found or escape
   sink_memo[function_node] = found
   return found
end

-- The function a value hands over, when the value is one. A handler written as
-- `object.apply = apply` names a function this file already defined, so the
-- value is followed to that definition - to the local's own definition, or, for a
-- name the file defines at its top level, through `globals`.
--
-- Only the first definition is taken: a value that is one of two functions
-- depending on a branch is still one registration, and reporting the other one
-- would report the same exposure twice.
local function function_of_value(value, globals, depth)
   depth = depth or 0
   if depth > 8 or type(value) ~= "table" then return nil end
   if value.tag == "Function" then return value end
   if value.tag == "Paren" then return function_of_value(value[1], globals, depth + 1) end
   if value.tag == "Id" then
      if value.var then
         for _, defined in ipairs(value.var.values or {}) do
            if defined.node and defined.node.tag == "Function" then return defined.node end
         end
      else
         return globals[value[1]]
      end
   end
   return nil
end

-- The dotted name of a callee, following a local bound to a required module:
-- `local ubus = require "ubus"` makes `ubus.add` the name it has at the global.
-- Every platform binding is a local alias for a module, and the rule context
-- resolves literal field access only, so the alias is followed here or not at
-- all.
--
-- A local with more than a handful of definitions names no module, so the walk
-- stops after ALIAS_DEFINITIONS of them. That keeps one lookup at a call site a
-- constant cost whatever the file does.
local ALIAS_DEFINITIONS = 4

local function callee_name(ctx, node, depth)
   depth = depth or 0
   if depth > 4 or type(node) ~= "table" then return nil end

   if node.tag == "Id" then
      if not node.var then return node[1] end
      local examined = 0
      for _, defined in ipairs(node.var.values or {}) do
         local value = defined.node
         if type(value) == "table" and value.tag == "Call" then
            if ctx:path_of(value[1]) == "require" then
               local module = ctx.literal(value[2])
               if module then return module end
            end
            local base = callee_name(ctx, value[1], depth + 1)
            if base then return base .. "." .. node[1] end
         end
         examined = examined + 1
         if examined >= ALIAS_DEFINITIONS then break end
      end
      return nil
   end

   if node.tag == "Index" and node[2] and node[2].tag == "String" then
      local base = callee_name(ctx, node[1], depth + 1)
      if base then return base .. "." .. node[2][1] end
   end

   return nil
end

-- The name a call is called by, from the rule context's own resolution of a
-- literal path and a local bound to a required module. A method call is named
-- `object:method`, which is the spelling the source registry uses.
local function call_path(ctx, node)
   if node.tag == "Invoke" then
      local method = node[2] and node[2][1]
      if type(method) ~= "string" then return nil end
      local base = callee_name(ctx, node[1])
      return (base and (base .. ":" .. method)) or method
   end
   return callee_name(ctx, node[1])
end

-- Target and value nodes of an assignment, one pair at a time. Both sides are
-- lists, of length one or more: `a = b` and `a, b = c, d` have the same shape
-- here, so a multiple assignment needs no separate reading.
local function each_assigned_pair(node, visit)
   local targets, values = node[1], node[2]
   if type(targets) ~= "table" or type(values) ~= "table" then return end
   for index = 1, #targets do
      local target, value = targets[index], values[index]
      if type(target) == "table" and type(value) == "table" then
         visit(target, value)
      end
   end
end

-- The dispatcher module, and the calls on it that name the function to run.
--
-- `entry`, `node` and `createtree` build the tree a name is attached to and take
-- no function; `call`, `post` and `post_on` are what a target is built from, and
-- their named argument is the function the web server will run. `post_on` is the
-- odd one out: its first argument is the form fields, not the function.
local DISPATCHER_MODULE = "luci.dispatcher"

local DISPATCHER_TARGETS = {
   call = 1,
   post = 1,
   post_on = 2,
}

-- A LuCI controller says so with `module("luci.controller.<name>")`, and
-- `package.seeall` is what puts the dispatcher in scope for the bare `entry` and
-- `call` the file then uses. That declaration is the evidence a bare name needs:
-- a program that happens to have a function called `entry` is not a dispatch
-- tree, and without the declaration nothing here is a registration.
local CONTROLLER_PREFIX = "luci.controller."

local function declares_controller(ctx, node)
   if ctx:path_of(node[1]) ~= "module" then return false end
   local name = ctx.literal(ctx.args_of(node)[1])
   if type(name) ~= "string" then return false end
   return name:sub(1, #CONTROLLER_PREFIX) == CONTROLLER_PREFIX
end

-- The last "." in a name, or nil. A dispatcher name is a dotted path whose last
-- segment is the call, so the base is everything before the last dot. This is a
-- plain forward scan for a literal character: no pattern is involved, so no name
-- can make it backtrack, and the cost is the number of dots in the name.
local function last_dot(name)
   local found, from = nil, 1
   while true do
      local at = name:find(".", from, true)
      if not at then return found end
      found, from = at, at + 1
   end
end

-- Which argument of a call names the function to run, when the call is a
-- dispatcher target, and whether the call is qualified by the dispatcher module.
-- A qualified call says so itself, whether it is spelled `luci.dispatcher.call` or
-- through a local bound to `require "luci.dispatcher"`. An unqualified one is only
-- a dispatcher call in a file that declared itself a controller, which is a
-- question about the whole file and so is answered after the walk.
local function dispatch_target(name)
   if type(name) ~= "string" then return nil end
   local at = last_dot(name)
   local key
   if at then
      if name:sub(1, at - 1) ~= DISPATCHER_MODULE then return nil end
      key = name:sub(at + 1)
   else
      key = name
   end
   local index = DISPATCHER_TARGETS[key]
   if not index then return nil end
   return index, at == nil
end

-- What this script hands back at its own top level: an rpcd plugin's object, a
-- CBI model's map, a module's table. Only a return at the file's own level
-- counts, because a return inside a function leaves that function and not the
-- module.
--
-- Returns the names the script returns and the table nodes it returns, the
-- second filled in from the names afterwards, since `return M` is only a returned
-- table if some definition of M is one.
local function returned_by_file(ctx)
   local names, tables = {}, {}
   local ast = ctx.chstate and ctx.chstate.ast
   if type(ast) ~= "table" then return names, tables end

   for index = 1, #ast do
      local statement = ast[index]
      if type(statement) == "table" and statement.tag == "Return" then
         for position = 1, #statement do
            local node = statement[position]
            if type(node) == "table" then
               if node.tag == "Id" then
                  names[node.var or node[1]] = node
               elseif node.tag == "Table" then
                  tables[node] = true
               end
            end
         end
      end
   end

   for _, node in pairs(names) do
      if node.var then
         for _, defined in ipairs(node.var.values or {}) do
            if defined.node and defined.node.tag == "Table" then tables[defined.node] = true end
         end
      end
   end

   return names, tables
end

-- A function with a sink, registered as a callable entry point.
--
-- One walk collects the facts every registration shape needs - the ubus objects
-- the file builds, the global functions a dispatcher can name, whether the file is
-- a controller - plus the registrations themselves, and the facts are resolved
-- afterwards. So the order a file happens to use in does not decide the answer,
-- and the walk stays one.
local function detect_exposed_handler(ctx)
   local state = taint_engine.new_state()
   local controller, objects, globals, methods, actions = false, {}, {}, {}, {}
   local ubus_tables = {}

   ctx:each_node(function(node)
      local tag = node.tag

      if tag == "Call" then
         if declares_controller(ctx, node) then controller = true end
         local name = callee_name(ctx, node[1])

         -- A method map handed straight to a ubus object is registered by the
         -- call that takes it, whatever the methods are called.
         if name and UBUS_OBJECT_CALLS[name] then
            for _, argument in ipairs(ctx.args_of(node)) do
               if type(argument) == "table" and argument.tag == "Table" then
                  ubus_tables[argument] = true
               end
            end
         end

         local index, bare = dispatch_target(name)
         if index then
            local argument = ctx.args_of(node)[index]
            local function_node = (argument and argument.tag == "Function") and argument or nil
            local named = argument and ctx.literal(argument) or nil
            if function_node or named then
               actions[#actions + 1] = {anchor = node, key = named,
                  inline = function_node, bare = bare}
            end
         end
         return
      end

      if tag == "Table" then
         -- A method written into a table literal, which is the same registration
         -- as a field assignment with the table named.
         for _, pair in ipairs(node) do
            if pair.tag == "Pair" then
               local key = ctx.literal(pair[1])
               if key and type(pair[2]) == "table" then
                  methods[#methods + 1] = {anchor = pair, key = key, value = pair[2],
                     table = node}
               end
            end
         end
         return
      end

      if tag ~= "Local" and tag ~= "Set" then return end
      local assignment = tag == "Set"

      each_assigned_pair(node, function(target, value)
         if target.tag == "Id" and value.tag == "Call" then
            local path = callee_name(ctx, value[1])
            if path and UBUS_OBJECT_CALLS[path] then
               objects[target.var or target[1]] = true
            end
         elseif target.tag == "Id" and value.tag == "Function" then
            -- A dispatcher resolves the name it is given in the controller's
            -- environment, so only a function the file defines at that
            -- environment's top level is a name it can reach.
            if not target.var then globals[target[1]] = value end
         elseif assignment and target.tag == "Index" then
            local key = ctx.literal(target[2])
            local base = target[1]
            if key and type(base) == "table" and base.tag == "Id" then
               methods[#methods + 1] = {anchor = target, key = key, value = value,
                  object = base.var or base[1]}
            end
         end
      end)
   end)

   local returned_names, returned_tables = returned_by_file(ctx)

   for _, method in ipairs(methods) do
      local is_ubus = (method.table and ubus_tables[method.table])
         or (method.object and objects[method.object])
      -- A field on an object the device hands out is a method whatever it is
      -- called. A field on a table this file returns is a method only when the
      -- receiving side calls it by that name: a module's `format` is a helper,
      -- and a map's `on_after_commit` is a hook the CBI framework runs.
      local exposed = is_ubus
         or ((method.object and returned_names[method.object]) and is_handler_name(method.key))
         or (method.table and returned_tables[method.table] and is_handler_name(method.key))
      if exposed then
         local function_node = function_of_value(method.value, globals)
         local sink = function_node and first_sink(ctx, function_node, state)
         if sink then
            ctx:emit("724", method.anchor, {
               name = function_node.name or method.key,
               exposed_as = method.key,
               sink = sink.path,
            })
         end
      end
   end

   for _, action in ipairs(actions) do
      -- A bare `call("x")` is the dispatcher's only in a controller; a qualified
      -- `luci.dispatcher.call("x")` is one wherever it appears.
      local function_node
      if not action.bare or controller then
         function_node = action.inline or globals[action.key]
      end
      local sink = function_node and first_sink(ctx, function_node, state)
      if sink then
         ctx:emit("724", action.anchor, {
            name = function_node.name or action.key,
            exposed_as = action.key,
            sink = sink.path,
         })
      end
   end
end

detectors[#detectors + 1] = detect_exposed_handler

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

return M


