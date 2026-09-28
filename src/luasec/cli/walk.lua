-- Input collection: files given on the command line, or directories walked
-- recursively. Deliberately conservative about what counts as a Lua file in
-- firmware: `.lua` plus extensionless files under cgi-bin, and files whose
-- first line looks like a Lua shebang or a Lua comment.
local walk = {}

local LUA_EXTENSIONS = {".lua", ".luac", ".rockspec"}

-- Extensions that are definitely not Lua. A firmware tree is mostly web assets
-- and translations, and scanning them produced hundreds of findings that were
-- all noise.
local NOT_LUA_EXTENSIONS = {
   ".js", ".uc", ".json", ".po", ".pot", ".css", ".html", ".htm", ".xml", ".svg",
   ".png", ".jpg", ".gif", ".woff", ".woff2", ".ttf", ".map", ".conf", ".sh",
   ".py", ".md", ".txt", ".ucode", ".patch", ".diff", ".pem", ".cer", ".p8",
   ".luadoc", ".awk", ".h", ".hpp", ".c", ".pl", ".dts", ".yml", ".yaml",
   ".pc", ".mk", ".rules", ".list", ".in", ".spec",
}

-- Names that are not Lua whatever they contain.
-- Keys are plain lowercased base names, matched exactly.
local NOT_LUA_NAMES = {
   ["makefile"] = true, ["gnumakefile"] = true, ["kbuild"] = true,
   ["kconfig"] = true, ["readme"] = true, ["license"] = true, ["copying"] = true,
   ["authors"] = true, ["changelog"] = true, ["changes"] = true, ["news"] = true,
   ["configure"] = true, ["install"] = true, ["todo"] = true,
}

-- Content markers of files that are not Lua whatever they are called. A patch
-- file starts with a diff header and a key with a PEM banner; both begin with
-- runs of dashes, which a Lua comment also does.
local NOT_LUA_HEADS = {
   "^diff %-%- ", "^%-%-%-%- ", "^%+%+%+ ", "^@@ ", "^Index: ", "^From ",
   "^Subject:", "^%-%-%-%-%-BEGIN", "^%-%-%-%-%-%-%-BEGIN", "^#!.*%b()$",
}

-- Extensionless scripts that are Lua: a CGI handler in cgi-bin, a Lua
-- interpreter shebang, a LuCI module.
local LUA_DIR_HINTS = {"cgi%-bin"}

local function is_lua_extension(path)
   local lower = path:lower()
   for _, extension in ipairs(NOT_LUA_EXTENSIONS) do
      if lower:sub(-#extension) == extension then return false end
   end
   for _, extension in ipairs(LUA_EXTENSIONS) do
      if lower:sub(-#extension) == extension then return true end
   end
   return nil
end

local function path_hint_match(path)
   for _, hint in ipairs(LUA_DIR_HINTS) do
      if path:find(hint) then return true end
   end
   return false
end

local LUA_OPENERS = {
   "^%-%-", "^local%s", "^require%s*%(", "^function%s", "^module%s*%(", "^return%s",
   "^%a+%s*=%s*function", "^do$", "^local%s+function",
}

-- Is this file Lua? An extension decides it when it is one we know. Otherwise
-- the content must look like Lua: a shebang naming lua, or an opener that a web
-- asset or a translation file would not have.
local function looks_like_lua(path)
   local name = path:match("([^/]+)$") or path
   if NOT_LUA_NAMES[name:lower()] or name:lower():match("^readme[%a-z0-9_.-]*$")
         or name:lower():match("^changelog[%a-z0-9_.-]*$") then
      return false
   end

   local by_extension = is_lua_extension(path)
   if by_extension == true then return true end
   if by_extension == false then return false end

   local handle = io.open(path, "rb")
   if not handle then return false end
   local head = handle:read(512)
   handle:close()
   if not head or head == "" then return false end
   if head:sub(1, 1) == "#" then
      return head:find("lua") ~= nil
   end
   for _, marker in ipairs(NOT_LUA_HEADS) do
      if head:match(marker) then
         if marker == "^#!.*%b()$" then
            return head:find("lua") ~= nil
         end
         return false
      end
   end
   for _, opener in ipairs(LUA_OPENERS) do
      if head:match(opener) then return true end
   end
   return false
end

-- Run a command with an untrusted path, without the path ever being part of the
-- command text.
--
-- luasec: ignore 708
-- Accepted, and worth saying why. This does hand a command to a shell, which is
-- the exposure 708 names, and luasec found it by scanning itself. What makes it
-- safe is the three lines below: the untrusted path never appears in the command
-- text, and the only variable in it, $p, comes from a temporary file we wrote.
-- The report of a suppression is itself a small safety net: this comment is
-- written, it says 708, and it is above the function.
--
-- Lua's %q escapes only " and \, so a directory named '/tmp/$(cmd)' would
-- otherwise run a command substitution inside luasec itself, and SECURITY.md says
-- filenames come from attackers. Command substitution output is not re-parsed as
-- shell syntax, so handing the path over as a file and reading it with $(cat ...)
-- is safe where interpolating it is not.
local function popen_with_path(command, path)
   local tmp = os.tmpname()
   local handle = assert(io.open(tmp, "wb"))
   handle:write(path)
   handle:close()
   local command_text = string.format(
      'p="$(cat %s)" || exit 0; %s', string.format("%q", tmp), command)
   return io.popen(command_text, "r"), tmp
end

-- Directories in `path` we are not allowed to read.
--
-- Neither find's exit status nor its stderr catches an unreadable EMPTY
-- directory on every platform, and an empty directory is exactly the case that
-- matters: it is the tree that looks complete and is not. BSD find has no
-- -readable, so each candidate is asked about with test -r.
--
-- Two traps, both of which produce a silently empty answer here: -prune
-- matches the top directory first and cuts the entire walk, and `-exec cmd {}
-- +` passes every match as trailing arguments, so a `sh -c` script has to loop
-- over "$@" rather than read "$1".
local function unreadable_dirs(path)
   local pipe, tmp = popen_with_path(
      'find "$p" -type d -exec sh -c \'for x in "$@"; do '
      .. 'test -r "$x" || printf "%s\\n" "$x"; done\' _ {} + 2>/dev/null', path)
   if not pipe then return {} end
   local out = {}
   for name in tostring(pipe:read("*a") or ""):gmatch("[^\n]+") do
      out[#out + 1] = name
   end
   pipe:close()
   os.remove(tmp)
   return out
end

local function list_dir(path)
   local files = {}
   -- Two signals, because neither one alone is reliable. find's exit status
   -- depends on the platform and on whether the unreadable directory happened
   -- to be empty; its stderr is where "Permission denied" actually lands. Both
   -- are checked, and either one means this listing is partial: "could not read
   -- this tree" and "this tree has no Lua in it" print the same thing otherwise,
   -- and the first must never be reported as the second.
   local errfile = os.tmpname()
   local pipe, tmp = popen_with_path(
      'find "$p" -type f -print0 2>' .. string.format("%q", errfile), path)
   if not pipe then
      os.remove(errfile)
      return nil, ("could not list directory: %s"):format(path)
   end
   -- NUL separated: a filename may contain a newline, and line-separated output
   -- would report it as two paths, one of which never existed. `lines` cannot
   -- take a NUL, so the whole stream is read and split here.
   local output = pipe:read("*a")
   local ok, reason = pipe:close()
   os.remove(tmp)

   local partial
   local complaints = io.open(errfile, "r")
   if complaints then
      local said = complaints:read("*a")
      complaints:close()
      -- Reported for the path, not for whatever find phrased it as.
      if said and said:gsub("%s", "") ~= "" then
         partial = ("could not list %s: permission denied reading part of the tree"):format(path)
      end
   end
   os.remove(errfile)

   -- find lists what it can and exits non-zero for the rest, so a partial
   -- listing is still a listing. Throwing it away would drop every readable
   -- file in the tree because of one unreadable directory; keeping it silent
   -- would claim we read the whole tree. Return both.
   if not partial and not ok and reason and reason ~= "" then
      partial = ("could not list %s: find %s"):format(path, reason)
   end

   for name in tostring(output or ""):gmatch("[^\0]+") do
      files[#files + 1] = name
   end
   -- Sorted here rather than by `sort -z`, which BSD sort does not have.
   table.sort(files)
   for _, unreadable in ipairs(unreadable_dirs(path)) do
      -- Reported for the directory that was skipped, which is the thing an
      -- operator has to go and fix.
      partial = ("could not read directory %s"):format(unreadable)
      break
   end
   if partial then return files, partial end
   return files
end

local function file_exists(path)
   local pipe, tmp = popen_with_path('test -f "$p" && echo yes', path)
   if not pipe then return false end
   local answer = pipe:read("*l")
   pipe:close()
   os.remove(tmp)
   return answer == "yes"
end

local function is_dir(path)
   local pipe, tmp = popen_with_path('test -d "$p" && echo yes', path)
   if not pipe then return false end
   local answer = pipe:read("*l")
   pipe:close()
   os.remove(tmp)
   return answer == "yes"
end

--- Expand a list of paths into a sorted, de-duplicated array of files to analyze.
-- Returns files plus a list of paths that could not be walked, or nil plus an
-- error message for a path that does not exist. A directory we cannot read is
-- collected as an error and the rest of the scan continues: the operator wants
-- both the findings and the knowledge that a piece was skipped.
function walk.collect(paths)
   local files, seen, errors = {}, {}, {}

   for _, path in ipairs(paths) do
      if is_dir(path) then
         local listed, list_error = list_dir(path)
         local skipped = path
         if not listed then
            errors[#errors + 1] = {message = list_error, path = skipped}
         else
         -- A partial listing is still a listing, and still an error: the files
         -- we did get are analyzed, and the part we could not read is reported.
         if list_error then
            errors[#errors + 1] = {message = list_error, path = skipped}
         end
         for _, file in ipairs(listed) do
            if not seen[file] and looks_like_lua(file) then
               seen[file] = true
               files[#files + 1] = file
            end
         end
         end
      elseif file_exists(path) then
         if not seen[path] then
            seen[path] = true
            files[#files + 1] = path
         end
      else
         return nil, "no such file: " .. path
      end
   end

   return files, errors
end

return walk
