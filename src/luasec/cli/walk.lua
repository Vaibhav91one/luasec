-- Input collection: files given on the command line, or directories walked
-- recursively. Deliberately conservative about what counts as a Lua file in
-- firmware: `.lua` plus extensionless files under cgi-bin, and files whose
-- first line looks like a Lua shebang or a Lua comment.
local walk = {}

local LUA_EXTENSIONS = {".lua", ".luac", ".rockspec"}
local LUA_DIR_HINTS = {"cgi%-bin", "www", "htdocs", "usr/lib/lua", "usr/share/lua", "etc/config"}

local function is_lua_extension(path)
   local lower = path:lower()
   for _, extension in ipairs(LUA_EXTENSIONS) do
      if lower:sub(-#extension) == extension then return true end
   end
   return false
end

local function path_hint_match(path)
   for _, hint in ipairs(LUA_DIR_HINTS) do
      if path:find(hint) then return true end
   end
   return false
end

local function looks_like_lua(path)
   local handle = io.open(path, "rb")
   if not handle then return false end
   local head = handle:read(256)
   handle:close()
   if not head or head == "" then return false end
   if head:sub(1, 1) == "#" then
      return head:find("lua") ~= nil
   end
   if is_lua_extension(path) then return true end
   if not path_hint_match(path) then return false end
   return head:find("%-%-") ~= nil or head:find("local%s") ~= nil or head:find("require%(") ~= nil
end

local function list_dir(path)
   local files = {}
   local pipe = io.popen("find " .. string.format("%q", path) ..
      " -type f 2>/dev/null | LC_ALL=C sort")
   if not pipe then return files end
   for line in pipe:lines() do
      if line ~= "" then files[#files + 1] = line end
   end
   pipe:close()
   return files
end

local function file_exists(path)
   local pipe = io.popen("test -f " .. string.format("%q", path) .. " && echo yes")
   if not pipe then return false end
   local answer = pipe:read("*l")
   pipe:close()
   return answer == "yes"
end

local function is_dir(path)
   local pipe = io.popen("test -d " .. string.format("%q", path) .. " && echo yes")
   if not pipe then return false end
   local answer = pipe:read("*l")
   pipe:close()
   return answer == "yes"
end

--- Expand a list of paths into a sorted, de-duplicated array of files to analyze.
-- Returns files, or nil plus an error message for paths that do not exist.
function walk.collect(paths)
   local files, seen = {}, {}

   for _, path in ipairs(paths) do
      if is_dir(path) then
         for _, file in ipairs(list_dir(path)) do
            if not seen[file] and looks_like_lua(file) then
               seen[file] = true
               files[#files + 1] = file
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

   return files
end

return walk
