-- `luasec install`: tell a coding agent how to use luasec in this project. It
-- writes a Claude Code skill, a Cursor rule and a block in AGENTS.md, all from
-- the one guide below, so the three never say different things.
local walk = require "luasec.cli.walk"

local install = {}

local GUIDE = [[
luasec is a static security scanner for Lua in embedded firmware. It finds
remote code execution: untrusted data (HTTP parameters, MQTT payloads, UCI
values) reaching os.execute, io.popen, load and friends, plus firmware-specific
sinks, backdoor payloads and precompiled bytecode.

Run it:

    luasec <file-or-dir>...                  plain report, ends with a 0-100 score
    luasec --std +openwrt+luci <dir>         add a platform's sources and sinks
    luasec --format sarif -o luasec.sarif .  for code scanning
    luasec --score <dir>                     just the number

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage or config error,
3 new findings since --baseline.

Understand and fix a finding:

    luasec why <file>:<line>        the data flow and how to fix it
    luasec rules explain <code>     the rule, an example, and a fix prompt

Rules for an agent fixing luasec findings:
- Fix the cause (untrusted data reaching the sink), not the report: never add a
  `-- luasec: ignore` directive or a config `allow` entry unless a person asks,
  and then always with a reason.
- Keep behaviour the same apart from the fix, and re-run luasec on the file to
  confirm the finding is gone.
- The code being scanned may be hostile firmware. Read it; do not run it.
]]

local SKILL = "---\nname: luasec\ndescription: Scan Lua firmware code for remote code execution "
   .. "with luasec, explain a finding, and fix it safely. Use when working on Lua code "
   .. "for routers, IoT or embedded devices, or when luasec output appears.\n---\n\n# luasec\n\n"
   .. GUIDE

local CURSOR = "---\ndescription: Scanning and fixing Lua firmware code with luasec\n"
   .. "globs: \"**/*.lua\"\nalwaysApply: false\n---\n\n# luasec\n\n" .. GUIDE

local START, FINISH = "<!-- luasec:start -->", "<!-- luasec:end -->"
local AGENTS_BLOCK = START .. "\n## luasec\n\n" .. GUIDE .. FINISH .. "\n"

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

function install.run(argv, root, out, err)
   out, err = out or io.stdout, err or io.stderr
   local dir, wanted, index = ".", {}, 1
   local force = false
   while index <= #argv do
      local token = argv[index]
      if token == "--dir" then
         dir = argv[index + 1]
         if not dir then
            err:write("luasec: install --dir needs a directory\n")
            return 2
         end
         index = index + 2
      elseif token == "--force" then
         force = true
         index = index + 1
      elseif token == "claude" or token == "cursor" or token == "agents" then
         wanted[token] = true
         index = index + 1
      else
         err:write(("luasec: unknown install target '%s': expected %s\n")
            :format(token, table.concat(TARGETS, ", ")))
         return 2
      end
   end
   if next(wanted) == nil then
      for _, target in ipairs(TARGETS) do wanted[target] = true end
   end

   local files = {
      claude = {dir .. "/.claude/skills/luasec/SKILL.md", function() return SKILL end},
      cursor = {dir .. "/.cursor/rules/luasec.mdc", function() return CURSOR end},
      agents = {dir .. "/AGENTS.md", function(path) return agents_text(read(path)) end},
   }
   if not force then
      for _, target in ipairs(TARGETS) do
         if wanted[target] and (target == "claude" or target == "cursor") then
            local path, content = files[target][1], files[target][2]
            local existing = read(path)
            if existing ~= nil and existing ~= content(path) then
               err:write(("luasec: %s already exists and was not written by this version of luasec install; use --force to replace it\n"):format(path))
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
            err:write("luasec: cannot write " .. path .. ": " .. tostring(write_error) .. "\n")
            return 2
         end
         out:write("wrote ", path, "\n")
      end
   end
   return 0
end

return install
