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
--                      /proc/1/cmdline is count 4 with segment 3 "cmdline".
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
   local chain = UCI_CONFIG_DIR .. config
   for index = 2, value_index - 1 do
      local part = ctx.literal(args[index])
      if part then chain = chain .. "." .. part end
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
local function detect_firmware_write(ctx)
   ctx:each_call(function(node, path)
      if not path then return end
      local api, path_node, mode = open_call(ctx, node, path)
      if not api then return end
      if not write_mode(mode) then return end

      local literal = ctx.literal(path_node)
      local prefix = literal or path_prefix(ctx, path_node)
      if not prefix then return end
      if not in_any_set({FLASH_PATHS, FIRMWARE_CONFIG_PATHS}, prefix) then return end

      -- One statement, one finding: under the espressif profile `file.open` is
      -- also declared as a 721 sink, and the dataflow pass has already reported
      -- that statement.
      if engine_reported(ctx, node, "721") then return end

      local extra = {name = path, sink = "firmware write", path = prefix}
      if literal then
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

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

return M
