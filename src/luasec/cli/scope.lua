-- Scoped scans for developers: only the files a change touched. It asks git which
-- files, then hands the list to the ordinary scan, so the report, the score and the
-- exit code mean the same as on a full run.
local walk = require "luasec.cli.walk"

local scope = {}

-- Every command here is a literal git invocation. The only variable parts are refs
-- and paths, and each goes through quote() so the shell reads it as one word.
local function run(command)
   -- lua-doctor: ignore 702  literal git commands; refs are quote()d and a ref that starts with "-" is refused
   -- lua-doctor: ignore 709  a ref read back from an earlier git call (the "file read" source)
   -- is quote()d again before it is used in the next one
   local pipe = io.popen(command .. " 2>/dev/null")
   if not pipe then return nil end
   local out = pipe:read("*a")
   local ok = pipe:close()
   return out, ok
end

-- A path handed to a shell, quoted so nothing in it is more than a name.
local function quote(text)
   return "'" .. tostring(text):gsub("'", "'\\''") .. "'"
end

local function lines(text)
   local list = {}
   for line in (text or ""):gmatch("[^\n]+") do list[#list + 1] = line end
   return list
end

local function in_repository()
   local out = run("git rev-parse --show-toplevel")
   return out and out:match("%S") ~= nil
end

-- The first base ref that exists, for --scope changed without --base.
local function default_base()
   for _, ref in ipairs({"origin/main", "main", "origin/master", "master"}) do
      local _, ok = run("git rev-parse --verify --quiet " .. quote(ref))
      if ok then return ref end
   end
   return nil
end

local function under(path, roots)
   for _, root in ipairs(roots) do
      local clean = root:gsub("^%./", ""):gsub("/+$", "")
      if clean == "" or clean == "." or path == clean or path:sub(1, #clean + 1) == clean .. "/" then
         return true
      end
   end
   return false
end

--- The Lua files to scan for `opts.staged` or `opts.scope == "changed"`. Returns
-- the list (possibly empty), or nil plus a message for the operator.
function scope.files(opts)
   if not in_repository() then
      return nil, "--scope and --staged need a git repository"
   end
   local names
   if opts.staged then
      names = lines(run("git diff --cached --name-only --diff-filter=ACMR"))
   else
      -- A ref that starts with "-" would be read by git as an option.
      if opts.base and opts.base:sub(1, 1) == "-" then
         return nil, "--base must be a ref, not an option"
      end
      local base = opts.base or default_base()
      if not base then return nil, "--scope changed needs --base <ref>" end
      local merge_base = run("git merge-base " .. quote(base) .. " HEAD")
      merge_base = merge_base and merge_base:match("%S+")
      if not merge_base then return nil, "--base " .. base .. " is not a ref git knows" end
      names = lines(run("git diff --name-only --diff-filter=ACMR " .. quote(merge_base)))
      if opts.include_untracked then
         -- --full-name: ls-files prints paths relative to the current directory by default,
         -- while diff prints them relative to the repository top; both must use the top.
         for _, name in ipairs(lines(run("git ls-files --others --exclude-standard --full-name"))) do
            names[#names + 1] = name
         end
      end
   end
   local top = (run("git rev-parse --show-toplevel") or ""):match("%S+")
   local prefix = (run("git rev-parse --show-prefix") or ""):gsub("%s+$", "")
   local files = {}
   for _, name in ipairs(names) do
      local rel = name
      if prefix ~= "" then
         if rel:sub(1, #prefix) ~= prefix then rel = nil end
         if rel then rel = rel:sub(#prefix + 1) end
      end
      if rel and under(rel, opts.paths) and walk.looks_like_lua(top .. "/" .. name) then
         -- Reported the way a full scan reports it, relative to where lua-doctor was run.
         files[#files + 1] = rel
      end
   end
   table.sort(files)
   return files
end

return scope
