-- Input collection: files given on the command line, or directories walked
-- recursively. Deliberately conservative about what counts as a Lua file in
-- firmware: `.lua` plus extensionless files under cgi-bin, `.html`/`.htm`
-- pages with a `<?lua` block (template.lua), and files whose first line looks
-- like a Lua shebang or a Lua comment. (`.lp` pages are analysed only when
-- named explicitly, never collected by a walk.)
local walk = {}

local template = require "luasec.cli.template"

local LUA_EXTENSIONS = {".lua", ".luac", ".rockspec"}

-- Extensions that are definitely not Lua. A firmware tree is mostly web assets
-- and translations, and scanning them produced hundreds of findings that were
-- all noise.
local NOT_LUA_EXTENSIONS = {
   ".js", ".uc", ".json", ".po", ".pot", ".css", ".lp", ".xml", ".svg",
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

-- A template page counts as Lua only when it holds a Lua block, which means
-- reading the whole file. Past 2 MiB the page is skipped rather than read.
local TEMPLATE_MAX_BYTES = 2000000

local function template_file_has_lua(path)
   local handle = io.open(path, "rb")
   if not handle then return false end
   local size = handle:seek("end")
   if not size or size > TEMPLATE_MAX_BYTES then
      handle:close()
      return false
   end
   handle:seek("set", 0)
   local text = handle:read("*a")
   handle:close()
   if not text then return false end
   return template.has_lua(text, path)
end

-- Is this file Lua? An extension decides it when it is one we know. Otherwise
-- the content must look like Lua: a shebang naming lua, or an opener that a web
-- asset or a translation file would not have.
local function looks_like_lua(path)
   local name = path:match("([^/]+)$") or path
   if NOT_LUA_NAMES[name:lower()] or name:lower():match("^readme[%a-z0-9_.-]*$")
         or name:lower():match("^changelog[%a-z0-9_.-]*$") then
      return false
   end

   if template.is_template_path(path) and path:lower():sub(-3) ~= ".lp" then
      return template_file_has_lua(path)
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
   -- A path that starts with "-" is read as an option by shell builtins
   -- and commands like find. Prefix it with "./" so it is a path.
   if path:sub(1, 1) == "-" then path = "./" .. path end
   handle:write(path)
   handle:close()
   local command_text = string.format(
      'p="$(cat %s; printf x)" || exit 0; p="${p%%x}"; %s', string.format("%q", tmp), command)
   return io.popen(command_text, "r"), tmp
end

-- How much one scan root is allowed to resolve to, and the environment variable
-- that moves the number.
--
-- -L is in the walk because a file behind a symlink that luasec never read is
-- the one failure this tool cannot have, and the price of -L is that a link to
-- a directory is walked once for every link that names it, with every copy
-- analyzed again. Measured on a 20,000-file tree with twenty links to one of its
-- own subdirectories: the walk collected 30,000 paths, 10,000 of them the same
-- files a second time, and the run took 3.6 s against 2.3 s for the same tree
-- without the links. One link named `root -> /` is the same growth without a
-- ceiling: find had listed past 200,000 paths in 5.9 s and was still going. The
-- shape of the tree is the attacker's to choose, so the growth cannot be left to
-- it, and neither can the ceiling: that walk now ends at the limit below.
--
-- 50,000 entries, which is a judgement and not a measurement: the largest
-- firmware rootfs in the wild is a few tens of thousands of files and a small one
-- a few thousand, so a limit in that range never fires on an image and every
-- pathology above does. It is a judgement because the cost of being wrong is not
-- symmetric: a limit that is too high costs a bounded scan, and a limit that is
-- too low reports a coverage gap and fails the build of a tree that was read in
-- full. Over the limit the run reports the gap and exits non-zero, on the rule
-- the rest of this file already follows: ground we did not cover is never
-- reported as a clean tree.
--
-- LUASEC_MAX_WALK_PATHS moves it, so a spec can prove the behaviour at a limit
-- no real tree reaches instead of creating 50,000 files to trip it.
local DEFAULT_MAX_WALK_PATHS = 50000
local MAX_WALK_PATHS_ENV = "LUASEC_MAX_WALK_PATHS"

local function walk_limit()
   local raw = os.getenv(MAX_WALK_PATHS_ENV)
   if raw == nil or raw == "" then return DEFAULT_MAX_WALK_PATHS end
   local value = tonumber(raw)
   -- A typo in the environment must not switch the bound off, and "0" is how
   -- people usually spell "no limit". There is no unlimited here: a value that
   -- is not a positive integer falls back to the number we ship, which is the
   -- direction that still costs the scan something it has to report.
   if not value or value < 1 or value % 1 ~= 0 then
      return DEFAULT_MAX_WALK_PATHS
   end
   return value
end

-- A path costs the budget whether it is a file we read, a directory we walked
-- or a link we resolved, and a directory a link names is charged twice over: it
-- is a path the scan resolved to, and it is a whole traversal about to be run.
-- What comes back is only ever acted on once, so the gap is reported against
-- the root that spent the budget rather than once per pass.
local function charge(state, count)
   state.left = state.left - count
   if state.left < 0 then state.over = true end
   return state.over
end

-- Read a NUL separated stream in chunks.
--
-- `read("*a")` is the obvious way and it is the wrong one: the whole stream
-- lands in memory before anything looks at it, which is the unbounded work the
-- limit exists to stop, one process later. A chunked read is what lets the
-- limit cut find off in the middle of a walk.
--
-- Two facts about filenames are carried here, because both are attacker-chosen
-- and both produce a silently wrong answer when dropped: a path may contain a
-- newline, so records are split on NUL and never on a line, and a path may
-- straddle a chunk boundary, so the tail of a chunk is carried into the next
-- read.
--
-- One record past the budget is enough to know the budget is gone. The overshoot
-- is one read rather than one record: whatever the last chunk carried, and not
-- one path more, because a path that is not read cannot be reported as read.
local READ_CHUNK = 65536

-- The link pass below writes one path in up to four records and the other two
-- write one each, so the reader is given as many records per path as the pass it
-- is reading can use. Running out of records always means running out of budget:
-- stopping the stream there instead would leave the rest of a legal listing
-- unread, which is a file missing from a report that says the tree was read. The
-- headroom is per pass rather than shared, because four times the limit read
-- before the walk is cut is four times the work the limit exists to bound.
local LINK_RECORDS_PER_PATH = 4
local ONE_RECORD_PER_PATH = 1

local function read_nul_stream(pipe, budget)
   local records, pending, over = {}, "", false
   while not over do
      local chunk = pipe:read(READ_CHUNK)
      if not chunk or chunk == "" then break end
      -- The leftover tail leads the next chunk, so a path split across two
      -- reads is still one path. The offset that walked this buffer starts again
      -- at one on the next one: the buffer it indexed is gone, and carrying the
      -- offset into the next one skips everything between the two starts, which
      -- is a file in a report that says the tree was read.
      local buffer, from = pending .. chunk, 1
      while true do
         local nul = buffer:find("\0", from, true)
         if not nul then break end
         local record = buffer:sub(from, nul - 1)
         from = nul + 1
         if record ~= "" then
            records[#records + 1] = record
            if #records > budget then over = true break end
         end
      end
      pending = over and "" or buffer:sub(from)
   end
   -- find terminates every path, so a tail here is a stream that ended without
   -- one. It is kept rather than dropped.
   if not over and pending ~= "" then records[#records + 1] = pending end
   return records, over
end

-- The question `rerooted` used to ask one link at a time, asked of many at once. The
-- link paths go to the shell as ONE NUL-separated file read by `xargs -0`, so no path
-- is ever spliced into a command, and xargs starts one sh for many links instead of
-- one per link. Returns a table: link path -> {inside = boolean, target = string|nil}.
-- `inside` is true when the link's absolute target exists under some ancestor of the
-- link, up to and never past the scan root; a target with a `..` component never counts.
local REROOT_SCRIPT = [[export LC_ALL=C
for p; do
  t=$(readlink -- "$p") || continue
  r=0
  case "$t" in
    /*)
      case "$t" in
        */../*|*/..) ;;
        *)
          d=$(dirname -- "$p")
          d=$(cd -P -- "$d" 2>/dev/null && printf "%s" "$PWD") || d=
          while [ -n "$d" ]; do
            if test -e "$d$t"; then r=1; break; fi
            if test ${#d} -le $N; then break; fi
            d=$(dirname -- "$d")
          done ;;
      esac ;;
  esac
  printf "%s\0%s\0%s\0" "$p" "$t" "$r"
done]]

local function reroot_batch(paths, anchor)
   local answers = {}
   if #paths == 0 then return answers end
   local list = os.tmpname()
   local handle = io.open(list, "wb")
   if not handle then return answers end
   for _, path in ipairs(paths) do handle:write(path, "\0") end
   handle:close()
   -- N is a number and `list` is a name os.tmpname chose; the script has no single quote.
   local command = ("N=%d xargs -0 sh -c '%s' _ < '%s' 2>/dev/null"):format(#anchor, REROOT_SCRIPT, list)
   -- luasec: ignore 702  the script is constant and N is a number; link paths travel as NUL bytes, never spliced
   local pipe = io.popen(command, "r")
   if pipe then
      local records = read_nul_stream(pipe, #paths * 3 + 3)
      pipe:close()
      for index = 1, #records - 2, 3 do
         answers[records[index]] = {inside = records[index + 2] == "1", target = records[index + 1]}
      end
   end
   os.remove(list)
   return answers
end

-- One pass over one directory, as three finds:
--
--   find -H "$p" -type f -print0
--   find -H "$p" -type d -exec ... test -r ...
--   find -H "$p" -type l -exec ... the link pass ...
--
-- -H follows the scan root when the operator points luasec at a link, and
-- nothing else. Every other link is resolved by expand_root below, which is what
-- keeps a directory from being walked twice through two links that name it.
--
-- Three finds and not one, because each find knows its own type. Working it out
-- from the spelling is the trap this walk already fell into: -type f matches a
-- symlink rather than its target, and a link reached with -H is still spelled
-- like a link, so a test on what find printed would call the root of a linked
-- directory a link and lose the tree.
--
-- Two traps in the shell below, both of which answer silently and wrongly:
--   - `-exec cmd {} +` passes every match as trailing arguments, so an sh -c
--     script has to loop over "$@" rather than read "$1"
--   - `test -e` on a link that resolves to a directory is true, so the link
--     pass asks what the target is before it asks whether there is one
local FILE_PASS = 'find -H "$p" -type f -print0 2>/dev/null'

-- Directories we cannot read. This is ground the walk did not cover, and it is
-- silent otherwise, because find lists what it can, exits 0, and the tree looks
-- complete.
--
-- Neither find's exit status nor its stderr catches an unreadable EMPTY
-- directory on every platform, and an empty directory is exactly the case that
-- matters: it is the tree that looks complete and is not. BSD find has no
-- -readable, so each candidate is asked about with test -r instead. This pass
-- writes bare paths, no kind, because it has only one kind to write.
local UNREADABLE_PASS =
   'find -H "$p" -type d -exec sh -c \'for x in "$@"; do '
   .. 'test -r "$x" || printf "%s\\0" "$x"; done\' _ {} + 2>/dev/null'

-- Every link, with what it names and, for a directory, where the kernel says
-- that directory is. Four records for a directory link -- the kind, the link,
-- "d", and the physical path -- and three for the rest.
--
-- `cd -P "$x" && printf "%s\0" "$PWD"` rather than readlink, because the question
-- the traversal asks is not "what does this link say" but "which directory is
-- this": four spellings of one directory are one directory and only the kernel
-- collapses them. It also costs no fork per link, and that is not a detail: a
-- firmware image carries a few hundred applet links, and 200 readlinks measured
-- 1.2 s of scan time on this machine, which is a second the walk spends before
-- it has read anything.
--
-- `cd -P` rather than `cd` plus `pwd -P`, because it leaves the answer in $PWD
-- and a shell can NUL-terminate a variable without a subshell. pwd writes a
-- newline, which in a NUL separated stream is not a terminator: the next
-- record's kind would be read as part of this path, and the pair would then be
-- one wrong path and one link nobody sees.
--
-- The cwd is put back after every link, because find's paths are relative when
-- the operator's scan root is, and a loop that left the shell in a directory
-- some link named would resolve the rest of them against the wrong tree. A cwd
-- that cannot be restored ends the pass, which the caller reports: a wrong
-- answer to which directory this is must not be a silent one.
--
-- A link to something that is neither a file nor a directory is counted and
-- nothing else: there is no Lua source in a device node or a socket, and a fifo
-- must never be opened at all, because reading one blocks until something
-- writes to it and one entry in an image would hang the scan.
local LINK_PASS =
   'find -H "$p" -type l -exec sh -c \''
   .. 'here=$(pwd -P) || exit 1; '
   .. 'for x in "$@"; do '
   .. 'if test -d "$x"; then '
   .. 'if cd -P "$x" 2>/dev/null; then '
   .. 'printf "l\\0%s\\0d\\0" "$x"; printf "%s\\0" "$PWD"; cd "$here" || exit 1; '
   .. 'else printf "u\\0%s\\0" "$x"; fi '
   .. 'elif test -f "$x"; then printf "l\\0%s\\0f\\0" "$x"; '
   .. 'elif test -e "$x"; then printf "l\\0%s\\0n\\0" "$x"; '
   .. 'else printf "l\\0%s\\0x\\0" "$x"; fi '
   .. 'done\' _ {} + 2>/dev/null'

-- Run one find pass and read what it printed. Returns the records, whether the
-- pass printed more of them than the budget allows, and find's exit status, which
-- is only worth acting on when nothing else explains it.
local function find_pass(dir, command, budget, per_path)
   local pipe, tmp = popen_with_path(command, dir)
   if not pipe then return nil, false, nil, nil end
   local records, over = read_nul_stream(pipe, budget * per_path + 1)
   -- Closing the pipe under a find that is still writing kills it, and then
   -- pclose reports a signal rather than an exit status. That is not a listing
   -- error: the reason it was stopped is the reason the run has to say out loud,
   -- and the caller already knows it, from `over`.
   -- The second value pclose gives back is the KIND of exit ("exit" or
   -- "signal") and the third is the number, so reporting the second alone wrote
   -- "find exit" into a message whose whole job is to say what happened.
   local ok, how, code = pipe:close()
   os.remove(tmp)
   return records, over, ok, how .. " " .. tostring(code)
end

-- Everything one pass found in one shape: the files to analyze, the links with
-- what they name, and the directories we could not read. Returns a second value
-- only when the listing itself failed, which is what the caller reports against
-- the directory.
local function scan_dir(dir, state)
   local scan = {files = {}, links = {}, unreadable = {}}

   -- The file pass runs first and is the one the limit can cut: find streams
   -- it, so reading past the budget closes the pipe under it and the walk
   -- stops where it is. The two passes below classify what it found, and
   -- neither can be cut: find collects their arguments and runs the shell once
   -- at the end of the walk, so a directory with three files and a million
   -- subdirectories prints almost nothing and walks all of them anyway. That
   -- was already true of the two coverage probes this replaces, and it is why
   -- this is checked here rather than after them: over the limit, the unreadable
   -- directories and the links of this directory are part of the rest the
   -- finding says was not read, so there is nothing to gain by asking.
   local files, over, ok, reason =
      find_pass(dir, FILE_PASS, state.left, ONE_RECORD_PER_PATH)
   if not files then
      return scan, ("could not list directory: %s"):format(dir)
   end
   scan.files = files
   state.over = over or state.over
   charge(state, #files)
   if state.over then return scan end

   local unreadable, unreadable_over, unreadable_ok =
      find_pass(dir, UNREADABLE_PASS, state.left, ONE_RECORD_PER_PATH)
   if unreadable then
      scan.unreadable = unreadable
      state.over = unreadable_over or state.over
      charge(state, #unreadable)
   end
   if state.over then return scan end

   local records, links_over, links_ok =
      find_pass(dir, LINK_PASS, state.left, LINK_RECORDS_PER_PATH)
   if records then
      state.over = links_over or state.over
      local index = 1
      while index <= #records do
         local kind, entry = records[index]:sub(1, 1), records[index + 1] or ""
         if kind == "u" then
            scan.unreadable[#scan.unreadable + 1] = entry
            index = index + 2
         elseif kind == "l" and entry ~= "" then
            local what = records[index + 2] or "x"
            local link = {path = entry, kind = what}
            if what == "d" then
               link.dir = records[index + 3]
               -- A stream the limit cut can end between a directory link's kind
               -- and the directory it names. It is reported as a link that
               -- resolves to nothing rather than indexed: we did not resolve it,
               -- which is what that finding says, and dropping it silently is
               -- the one answer that is not allowed here.
               if link.dir == nil or link.dir == "" then link.kind = "x" end
            end
            scan.links[#scan.links + 1] = link
            index = index + (what == "d" and 4 or 3)
         else
            -- A record this reader has no shape for, which is a stream that
            -- ended in the middle of one. The budget is what stopped it, and the
            -- gap for that is already accounted for.
            index = index + 1
         end
      end
      charge(state, #scan.links)
   end

   -- find lists what it can and exits non-zero for the rest, so a partial
   -- listing is still a listing: throwing it away would drop every readable
   -- file because of one directory we could not read, and keeping it silent
   -- would claim we read the whole tree. The named directory explains the exit
   -- status, so the fallback below is only for what that does not explain.
   if not ok and not unreadable_ok and not links_ok and #scan.unreadable == 0
      and reason and reason ~= "" then
      return scan, ("could not list %s: find %s"):format(dir, reason)
   end
   return scan
end

-- The physical path of a directory, as the kernel resolves it.
--
-- `cd -P -- "$p" && printf "%s\0" "$PWD"`, and not a string comparison in Lua: this
-- is what turns `x`, `./x`, `a/../x` and a path that goes through another link
-- into one string, and a lexical comparison gets that wrong in the one direction
-- this tool cannot afford -- a link inside the root to somewhere else entirely,
-- written so that the string still looks like it stays inside.
--
-- The answer is read whole and the NUL stripped by hand, so a directory name
-- that contains a newline survives: reading a line of it would ask a different
-- question than the one asked, and no newline is trimmed at all, so a name that
-- ends in one is not renamed.
local function physical_dir(path)
   local pipe, tmp = popen_with_path(
      'test -d "$p" || exit 0; cd -P -- "$p" && printf "%s\\0" "$PWD"', path)
   if not pipe then return nil end
   local answer = tostring(pipe:read("*a") or "")
   pipe:close()
   os.remove(tmp)
   if answer:sub(-1) == "\0" then answer = answer:sub(1, -2) end
   if answer == "" then return nil end
   return answer
end

-- Names that cannot be Lua source: a shared library, an object, an archive or an image.
local BINARY_LINK_SUFFIXES = {".so", ".a", ".ko", ".o", ".bin", ".img", ".gz", ".xz",
   ".bz2", ".lzma", ".zip", ".tar", ".ubi", ".dtb"}

-- A link that names something that cannot be Lua by its own name: an extension
-- the walk never treats as Lua, or a binary suffix (libfoo.so, libfoo.so.1.2).
-- A dangling link has no content to look at, so the name is all there is.
local function cannot_be_lua(path)
   local lower = path:lower()
   if is_lua_extension(lower) == false then return true end
   -- A dangling link names no content to check for a Lua block, so a template
   -- name is not ground we know we missed, as a dangling .html never was.
   if template.is_template_path(lower) then return true end
   if lower:find("%.so%.[%d%.]+$") then return true end
   for _, suffix in ipairs(BINARY_LINK_SUFFIXES) do
      if lower:sub(-#suffix) == suffix then return true end
   end
   return false
end

-- Everything one scan root resolves to: the files under it, plus the ground its
-- symlinks name that the walk has not already covered.
--
-- The links are followed here rather than by find's -L, and that is the whole
-- of it. -L hands the decision to find, which walks every path a link names, so
-- a directory two links reach is walked twice, three times, and once per link an
-- attacker adds. Here a link is resolved to ONE physical path first, and a
-- directory is walked the first time any link lands on it and never again:
--
--   - covered is decided by the physical path, so it does not matter how many
--     different links spell the same directory, and a link to a path inside the
--     root names no new ground, because the pass below already listed it
--   - the walk is a queue rather than a recursion and each directory enters it
--     at most once, so a link to its own ancestor, a pair of links pointing at
--     each other, and a fan of links pointing outward all end: the set of walked
--     directories only grows, and growing it is what costs against the bound
local function expand_root(root)
   local limit = walk_limit()
   local state = {left = limit, limit = limit, over = false}
   local files, problems, dangling = {}, {}, {}

   local anchor = physical_dir(root)
   if not anchor then
      return nil, ("could not list directory: %s"):format(root)
   end
   -- A trailing slash keeps the prefix test right for a root of "/", where
   -- anchor .. "/" would be "//" and nothing is under it.
   local inside_prefix = anchor:gsub("/$", "") .. "/"
   local walked = {[anchor] = true}
   local queue, head = {root}, 1

   while queue[head] and not state.over do
      local dir = queue[head]
      head = head + 1
      local scan, listing_error = scan_dir(dir, state)
      if listing_error then
         problems[#problems + 1] = {message = listing_error, path = dir}
      end
      for _, file in ipairs(scan.files) do
         files[#files + 1] = file
      end
      for _, path in ipairs(scan.unreadable) do
         -- Reported against the directory that was skipped, which is the thing
         -- an operator has to go and fix, rather than the scan root.
         problems[#problems + 1] = {
            message = ("could not read directory %s"):format(path),
            path = path,
         }
      end
      local checks = {}
      for _, link in ipairs(scan.links) do
         if link.kind == "f" then
            checks[#checks + 1] = link.path
         elseif link.kind == "d" then
            local covered = link.dir == anchor or link.dir:sub(1, #inside_prefix) == inside_prefix
            if not covered then checks[#checks + 1] = link.path end
         elseif link.kind == "x" and not cannot_be_lua(link.path) then
            checks[#checks + 1] = link.path
         end
      end
      local verdict = reroot_batch(checks, anchor)
      for _, link in ipairs(scan.links) do
         if link.kind == "f" then
            -- Read under the name the tree gives the link, so the finding lands
            -- where an operator looks for it; opening it follows the link, so the
            -- bytes analyzed are the target's. An absolute link whose target has a
            -- copy under the scan root names that copy, which is analysed at its
            -- real path, so following it here would read the HOST's file instead.
            local answer = verdict[link.path]; if not (answer and answer.inside) then files[#files + 1] = link.path end
         elseif link.kind == "d" then
            local covered = link.dir == anchor
               or link.dir:sub(1, #inside_prefix) == inside_prefix
            if not covered then
               -- An absolute link in an extracted image may still name ground
               -- inside the root: the pass above resolved it against this
               -- machine instead. When that copy exists under the root it is
               -- analyzed at its real path already, so this names no new
               -- ground and is not walked a second time.
               local answer = verdict[link.path]; if answer and answer.inside then covered = true end
            end
            if not covered and not walked[link.dir] then
               walked[link.dir] = true
               if charge(state, 1) then break end
               queue[#queue + 1] = link.dir
            end
         elseif link.kind == "x" then
            -- A link that resolves to nothing, and a link that resolves to
            -- itself are the same report: we could not read what this names.
            if not cannot_be_lua(link.path) then dangling[#dangling + 1] = {path = link.path, target = verdict[link.path] and verdict[link.path].target, inside = verdict[link.path] and verdict[link.path].inside} end
         end
      end
   end

   -- An absolute link in an extracted image names its target as the device saw
   -- it, so each dangling link is read against the scan root before it is
   -- called a gap: when that copy exists the target is analyzed at its real
   -- path already. What is still missing is one finding per scan root, not one
   -- per link.
   local missing = {}
   for _, entry in ipairs(dangling) do
      if not entry.inside then missing[#missing + 1] = {path = entry.path, target = entry.target} end
   end
   if #missing == 1 then
      problems[#problems + 1] = {
         message = ("could not resolve symlink %s"):format(missing[1].path),
         path = missing[1].path,
      }
   elseif #missing > 1 then
      local first = missing[1]
      local also = {}
      for index = 2, math.min(#missing, 4) do also[#also + 1] = missing[index].path end
      local message = ("could not resolve symlink %s and %d more (each names a target "
         .. "that is missing, or an absolute path with no copy under the scanned root; "
         .. "for example %s -> %s)"):format(first.path, #missing - 1, first.path,
            first.target or "?")
      if #also > 0 then message = message .. "; also " .. table.concat(also, ", ") end
      problems[#problems + 1] = {message = message, path = root}
   end

   if state.over then
      -- One finding, against the root that spent the budget, and it names the
      -- number and the way out of it: an operator who hits this on an image that
      -- is legitimately that big needs to be able to raise it without reading
      -- this file first.
      problems[#problems + 1] = {
         message = ("%s resolved to more than %d paths, so the rest of it "
            .. "was not read; %s raises the limit")
            :format(root, state.limit, MAX_WALK_PATHS_ENV),
         path = root,
      }
   end
   -- Sorted here rather than by `sort -z`, which BSD sort does not have.
   table.sort(files)
   if #problems > 0 then return files, problems end
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
--
-- `seen` de-duplicates by path, which is what two roots naming the same file
-- need and is deliberately not content identity: a hard link or a bind mount
-- reachable at two paths inside one tree is ground the operator can see at both
-- of them, and dropping one is a coverage hole dressed as an optimization.
--- Create a directory and its parents, for the commands that write files into
-- a project. The path is handed over the way the walk hands one over, through
-- popen_with_path, so a directory named '$(cmd)' is a name and nothing else.
-- Returns true, or nil when the directory does not exist afterwards.
function walk.mkdir_p(path)
   local pipe, tmp = popen_with_path('mkdir -p -- "$p" && printf ok', path)
   local out = pipe:read("*a")
   pipe:close()
   os.remove(tmp)
   return out == "ok" or nil
end

--- Make a file executable. The path is handed over the way the walk hands one
-- over, so a name with shell syntax in it is only a name. Returns true or nil.
function walk.make_executable(path)
   local pipe, tmp = popen_with_path('chmod +x -- "$p" && printf ok', path)
   local out = pipe:read("*a")
   pipe:close()
   os.remove(tmp)
   return out == "ok" or nil
end

--- Hooks directory of the repository at dir, via git so worktrees work.
-- Returns the path or nil when dir is not in a git repository.
function walk.git_hooks_dir(dir)
   local pipe, tmp = popen_with_path('cd "$p" && git rev-parse --git-path hooks', dir)
   if not pipe then return nil end
   local out = pipe:read("*a") or ""
   pipe:close()
   os.remove(tmp)
   out = out:gsub("%s+$", ""):gsub("^%s+", "")
   if out == "" then return nil end
   if out:sub(1, 1) == "/" then return out end
   return dir:gsub("/$", "") .. "/" .. out
end

function walk.collect(paths)
   local files, seen, errors = {}, {}, {}

   for _, path in ipairs(paths) do
      if is_dir(path) then
         local listed, list_error = expand_root(path)
         local skipped = path
         if not listed then
            errors[#errors + 1] = {message = list_error, path = skipped}
         else
         -- A partial listing is still a listing, and still an error: the files
         -- we did get are analyzed, and every directory we could not read and
         -- every link we could not resolve is reported, each against its own
         -- path, and a root that outgrew the limit is reported against itself.
         for _, problem in ipairs(list_error or {}) do
            errors[#errors + 1] = problem
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

walk.looks_like_lua = looks_like_lua

return walk
