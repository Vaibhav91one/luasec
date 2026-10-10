-- `lua-doctor install`: tell a coding agent how to use lua-doctor in this project. It
-- writes a Claude Code skill, a Cursor rule and a block in AGENTS.md, all from
-- the one guide below, so the three never say different things.
local walk = require "luadoctor.cli.walk"

local install = {}

local GUIDE = [[
lua-doctor is a static security scanner for Lua in embedded firmware. It finds
remote code execution: untrusted data (HTTP parameters, MQTT payloads, UCI
values) reaching os.execute, io.popen, load and friends, plus firmware-specific
sinks, backdoor payloads and precompiled bytecode.

Run it:

    lua-doctor <file-or-dir>...                  plain report, ends with a 0-100 score
    lua-doctor --std +openwrt+luci <dir>         add a platform's sources and sinks
    lua-doctor --format sarif -o lua-doctor.sarif .  for code scanning
    lua-doctor --score <dir>                     just the number

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage or config error,
3 new findings since --baseline.

Understand and fix a finding:

    lua-doctor why <file>:<line>        the data flow and how to fix it
    lua-doctor rules explain <code>     the rule, an example, and a fix prompt

Rules for an agent fixing lua-doctor findings:
- Fix the cause (untrusted data reaching the sink), not the report: never add a
  `-- lua-doctor: ignore` directive or a config `allow` entry unless a person asks,
  and then always with a reason.
- Keep behaviour the same apart from the fix, and re-run lua-doctor on the file to
  confirm the finding is gone.
- The code being scanned may be hostile firmware. Read it; do not run it.
]]

local SKILL = "---\nname: lua-doctor\ndescription: Scan Lua firmware code for remote code execution "
   .. "with lua-doctor, explain a finding, and fix it safely. Use when working on Lua code "
   .. "for routers, IoT or embedded devices, or when lua-doctor output appears.\n---\n\n# lua-doctor\n\n"
   .. GUIDE

local CURSOR = "---\ndescription: Scanning and fixing Lua firmware code with lua-doctor\n"
   .. "globs: \"**/*.lua\"\nalwaysApply: false\n---\n\n# lua-doctor\n\n" .. GUIDE

local START, FINISH = "<!-- lua-doctor:start -->", "<!-- lua-doctor:end -->"
local AGENTS_BLOCK = START .. "\n## lua-doctor\n\n" .. GUIDE .. FINISH .. "\n"

local HOOK_BEGIN, HOOK_END = "# lua-doctor: begin", "# lua-doctor: end"
local HOOK_BLOCK = [[# lua-doctor: begin
# Scan the files staged for this commit. A finding at or above high severity and
# at least medium confidence stops it; shape-only findings (low confidence) are for
# a full scan, so this hook stays quiet enough to keep.
if command -v lua-doctor >/dev/null 2>&1; then
   lua-doctor --staged --fail-on high --min-confidence medium || exit 1
else
   echo "lua-doctor: not on PATH, skipping the pre-commit scan" >&2
fi
# lua-doctor: end
]]

local TARGETS = {"claude", "cursor", "agents"}

local function read(path)
   local handle = io.open(path, "rb")
   if not handle then return nil end
   local text = handle:read("*a")
   handle:close()
   return text
end

local function write(path, text)
   local dir = path:match("^(.*)/[^/]*$")
   if dir and not walk.mkdir_p(dir) then return nil, "cannot create " .. dir end
   local handle, open_error = io.open(path, "wb")
   if not handle then return nil, open_error end
   handle:write(text)
   handle:close()
   return true
end

-- AGENTS.md belongs to the project, so only the marked block is ours: replaced
-- in place when it is there, appended when it is not.
local function agents_text(existing)
   if not existing or existing == "" then return AGENTS_BLOCK end
   local before, after = existing:match("^(.-)" .. START:gsub("%p", "%%%0") .. ".-"
      .. FINISH:gsub("%p", "%%%0") .. "\n?(.*)$")
   if before then return before .. AGENTS_BLOCK .. after end
   return existing .. (existing:sub(-1) == "\n" and "\n" or "\n\n") .. AGENTS_BLOCK
end

-- The pre-commit hook lives in the repository's hooks directory, and nowhere
-- else: this writer reads and writes exactly one path under it.
local function install_hook(dir, force, out, err)
   local hooks = walk.git_hooks_dir(dir)
   if not hooks then
      err:write("lua-doctor: --hook needs a git repository\n")
      return 2
   end
   local path = hooks .. "/pre-commit"
   local existing = read(path)
   if existing == nil then
      local ok, write_error = write(path, "#!/bin/sh\n" .. HOOK_BLOCK)
      if not ok then
         err:write("lua-doctor: cannot write " .. path .. ": " .. tostring(write_error) .. "\n")
         return 2
      end
      walk.make_executable(path)
      out:write("wrote " .. path .. "\n")
      return 0
   end
   if existing:find(HOOK_BEGIN, 1, true) and existing:find(HOOK_END, 1, true) then
      local before, after = existing:match("^(.-)" .. HOOK_BEGIN:gsub("%p", "%%%0") .. ".-"
         .. HOOK_END:gsub("%p", "%%%0") .. "\n?(.*)$")
      if before then
         local updated = before .. HOOK_BLOCK .. after
         if updated ~= existing then
            local ok, write_error = write(path, updated)
            if not ok then
               err:write("lua-doctor: cannot write " .. path .. ": " .. tostring(write_error) .. "\n")
               return 2
            end
         end
         out:write("updated " .. path .. "\n")
         return 0
      end
   end
   if not force then
      err:write(("lua-doctor: %s already exists; use --force to add the lua-doctor block to it\n"):format(path))
      return 2
   end
   local sep
   if existing == "" then
      sep = ""
   elseif existing:sub(-2) == "\n\n" then
      sep = ""
   elseif existing:sub(-1) == "\n" then
      sep = "\n"
   else
      sep = "\n\n"
   end
   local ok, write_error = write(path, existing .. sep .. HOOK_BLOCK)
   if not ok then
      err:write("lua-doctor: cannot write " .. path .. ": " .. tostring(write_error) .. "\n")
      return 2
   end
   out:write("updated " .. path .. "\n")
   return 0
end

function install.run(argv, root, out, err)
   out, err = out or io.stdout, err or io.stderr
   local dir, wanted, index = ".", {}, 1
   local force = false
   local hook = false
   while index <= #argv do
      local token = argv[index]
      if token == "--dir" then
         dir = argv[index + 1]
         if not dir then
            err:write("lua-doctor: install --dir needs a directory\n")
            return 2
         end
         index = index + 2
      elseif token == "--force" then
         force = true
         index = index + 1
      elseif token == "--hook" then
         hook = true
         index = index + 1
      elseif token == "claude" or token == "cursor" or token == "agents" then
         wanted[token] = true
         index = index + 1
      else
         err:write(("lua-doctor: unknown install target '%s': expected %s\n")
            :format(token, table.concat(TARGETS, ", ")))
         return 2
      end
   end
   if next(wanted) == nil and not hook then
      for _, target in ipairs(TARGETS) do wanted[target] = true end
   end

   local files = {
      claude = {dir .. "/.claude/skills/lua-doctor/SKILL.md", function() return SKILL end},
      cursor = {dir .. "/.cursor/rules/lua-doctor.mdc", function() return CURSOR end},
      agents = {dir .. "/AGENTS.md", function(path) return agents_text(read(path)) end},
   }
   if not force then
      for _, target in ipairs(TARGETS) do
         if wanted[target] and (target == "claude" or target == "cursor") then
            local path, content = files[target][1], files[target][2]
            local existing = read(path)
            if existing ~= nil and existing ~= content(path) then
               err:write(("lua-doctor: %s already exists and was not written by this version of lua-doctor install; use --force to replace it\n"):format(path))
               return 2
            end
         end
      end
   end
   for _, target in ipairs(TARGETS) do
      if wanted[target] then
         local path, content = files[target][1], files[target][2]
         local ok, write_error = write(path, content(path))
         if not ok then
            err:write("lua-doctor: cannot write " .. path .. ": " .. tostring(write_error) .. "\n")
            return 2
         end
         out:write("wrote ", path, "\n")
      end
   end
   if hook then
      return install_hook(dir, force, out, err)
   end
   return 0
end

return install
