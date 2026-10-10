local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local profiles = require "luadoctor.registry.profiles"

-- Every dotted name in the registry is a claim: some function exists, and the
-- command or value it reads is where `arg` says it is. Four such claims were
-- wrong when #268 was filed, all in one family, and none of them could be
-- caught by running the tool over the corpus -- a declaration of a function
-- nobody calls is indistinguishable, from the outside, from a declaration of a
-- function that is merely quiet:
--
--   nixio.execp, nixio.exece   not declared at all (0 findings, 100/100)
--   nixio.process.execute      declared; nixio exports no such function
--   nixio.process.exec         declared; `nixio.process` is not a module
--
-- So this spec reads the implementations out of corpus/ and asserts that every
-- name the registry declares is one the code actually exports.
--
-- What that catches and what it does not, because the two are different
-- failures with different fixes. It catches the last three lines above: a
-- declaration naming something that is not there, which is a data change. It
-- cannot catch the first, because a function that is not declared has no
-- declaration to check -- that is a missing row, and the only thing that finds
-- it is reading the C and writing the declaration. What this spec guarantees is
-- that the next *dead* declaration is found by running the tests rather than by
-- reading, and that is the half of the problem that recurs.
--
-- A declaration the corpus cannot speak for is neither of those. It is neither
-- dead nor verified, so it is bucketed and printed by name on every run rather
-- than passing under a green line; see report_unverifiable below.
--
-- corpus/ is not in git (.gitignore; `make corpus` clones it), so a checkout
-- without it can derive nothing. It says so in four lines rather than going
-- quiet, which is the same rule `make precision` follows for the same reason: a
-- skipped measurement is not evidence.

local CORPUS = "corpus"

-- Namespaces that are the Lua language rather than a firmware API. The corpus
-- happens to contain LuaJIT's minilua.c, which registers a table named `os`
-- and one named `io`; those are not the `os.execute` and `io.popen` the
-- registry means, so the standard library is never checked against them.
local LUA_STANDARD = {
   _G = true, bit = true, coroutine = true, debug = true, ffi = true,
   io = true, jit = true, math = true, os = true, package = true,
   string = true, table = true, utf8 = true,
}

-- Declared names the corpus does not export, each with the reason it is still
-- here. A name appearing in this list is a decision somebody made on purpose,
-- so adding one is a review, and removing a name that is NOT in this list is
-- what turns this spec red. That asymmetry is the whole design: the failures
-- that matter are new declarations, and known-bad ones are visible rather than
-- silently tolerated.
local KNOWN_NOT_EXPORTED = {
   -- luci/http.lua:264 is `urldecode = util.urldecode`: a name the module
   -- publishes by assignment, which the export reader does not follow. The call
   -- spelling `luci.http.urldecode(x)` is real (luci-app-commands uses it).
   ["luci.http.urldecode"] = "published by alias assignment, not by a function definition",
}

--------------------------------------------------------------------------------
-- reading the corpus

local function slurp(path)
   local handle = io.open(path, "r")
   if not handle then return nil end
   local source = handle:read("*a")
   handle:close()
   return source
end

local function corpus_present()
   local handle = io.open(CORPUS, "r")
   if not handle then return false end
   handle:close()
   return true
end

--------------------------------------------------------------------------------
-- the corpus, read once

-- Before the derivations, not after: a local declared below the function that
-- closes over it is not the local the function reads, and the symptom is an
-- unrelated nil further up.
local function collect_corpus_files()
   local pipe = assert(io.popen(
      ("find -L %s -type f 2>/dev/null | LC_ALL=C sort"):format(CORPUS)))
   local c_files, lua_files = {}, {}
   for line in pipe:lines() do
      if line:match("%.c$") then
         c_files[#c_files + 1] = line
      elseif line:match("%.lua$") then
         lua_files[#lua_files + 1] = line
      end
   end
   pipe:close()
   return c_files, lua_files
end

local have_corpus = corpus_present()
local corpus_c_files, corpus_lua_files = {}, {}
if have_corpus then
   corpus_c_files, corpus_lua_files = collect_corpus_files()
end

--------------------------------------------------------------------------------
-- C bindings

-- C comments hold example registrations, so they come out before anything is
-- read. `//` is matched only after a non-newline so a lone `/` at the start of
-- a line is not eaten with the rest of it.
local function strip_comments(source)
   source = source:gsub("/%*.-%*/", " ")
   source = source:gsub("([^\n])//[^\n]*", "%1 ")
   return source
end

-- The names in `{"exec", nixio_exec},` and in `{ "new", cidr_new },`. LuCI's C
-- puts a space after the brace and nixio's does not.
local function array_names(source, array)
   local start = source:find("%f[%w_]" .. array .. "%s*%[%s*%]%s*=%s*{", 1)
   if not start then return nil end
   local stop = source:find("};", start, true)
   if not stop then return nil end
   local names = {}
   for name in source:sub(start, stop):gmatch('{%s*"([%w_]+)"%s*,') do
      names[#names + 1] = name
   end
   return names
end

-- Every `type name(args) {` ... `}` in a C file. Not a C parser: one function
-- per top-level block, which is the shape every Lua binding in the corpus is
-- written in, and the only brace that opens a block at column 0 closes it.
local function c_functions(source)
   local functions, current = {}, nil
   for line in source:gmatch("([^\n]*)\n") do
      if not current then
         local name = line:match("^[%w_]+%s+([%w_]+)%s*%([^%s].*%)%s*{")
         if name then current = {name = name, body = {}} end
      elseif line:match("^%s*}") then
         functions[#functions + 1] = {name = current.name, body = table.concat(current.body, "\n")}
         current = nil
      else
         current.body[#current.body + 1] = line
      end
   end
   return functions
end

-- module -> {name = true}, for everything the corpus's C code binds to Lua.
--
-- Three shapes matter and one of them is the reason this spec exists.
--
--   nixio, luci.ip     `luaL_register(L, "nixio", R)`, or a #define'd name, or
--                      a bare `luaopen_nixio`.
--   nixio.fs, nixio.bit
--                      an `nixio_open_<sub>` that pushes its own table and
--                      names it: `lua_newtable(); luaL_register(NULL, R);
--                      lua_setfield(L, -2, "<sub>")`.
--   ... and the rest      an `nixio_open_<sub>` that registers straight into the
--                      table already on the stack. Ten of nixio's seventeen
--                      openers are written that way, including `process`.
--
-- So `process.c` does NOT define a `nixio.process` namespace. Its functions
-- land on `nixio` itself, and the exports are `nixio.exec`, `nixio.execp`,
-- `nixio.exece`, `nixio.getenv`. Which of the two an opener does is read off
-- the source, because the two differ by one line and getting it wrong is how a
-- namespace that never existed ends up in the registry.
local function derive_c_modules()
   local modules, prefix_of_module = {}, {}

   local function export(module, name)
      modules[module] = modules[module] or {}
      modules[module][name] = true
   end

   -- Pass one: every module the corpus names, and every registration array,
   -- with the openers left unresolved because process.c cannot say which
   -- module it belongs to on its own -- nixio.c is the file that says.
   local openers, sources = {}, {}
   for index, path in ipairs(corpus_c_files) do
      local source = strip_comments(slurp(path))
      if source then
         sources[#sources + 1] = source
         local here = #sources

         local defines = {}
         for macro, value in source:gmatch('#define%s+([%w_]+)%s+"([%w_%.]+)"') do
            defines[macro] = value
         end

         for module, array in
            source:gmatch('luaL_register%s*%(%s*L%s*,%s*"([%w_%.]+)"%s*,%s*([%w_]+)%s*%)') do
            prefix_of_module[module] = module
            openers[#openers + 1] = {array = array, module = module, source = here}
         end
         for macro, array in
            source:gmatch('luaL_register%s*%(%s*L%s*,%s*([%w_]+)%s*,%s*([%w_]+)%s*%)') do
            if defines[macro] then
               prefix_of_module[defines[macro]] = defines[macro]
               openers[#openers + 1] = {array = array, module = defines[macro], source = here}
            end
         end
         for name in source:gmatch("luaopen_([%w_]+)%s*%(") do
            prefix_of_module[name] = name
         end
         _ = index
      end
   end

   -- Pass two: the openers, now that `nixio` is known to be nixio's module.
   for index, source in ipairs(sources) do
      for _, fn in ipairs(c_functions(source)) do
         local prefix, sub = fn.name:match("^([%w_]+)_open_([%w_]+)$")
         local parent = prefix and prefix_of_module[prefix]
         if parent then
            -- The submodule is the one an opener names after itself. Only a
            -- table that is pushed and then given a field becomes
            -- `nixio.<sub>`, and the field it is given is the opener's own
            -- name: `nixio_open_file` ends with `lua_setfield(L, -2,
            -- "meta_file")` and never with "file", so file.c is flat.
            local installs_submodule =
               fn.body:find('lua_setfield%s*%(%s*L%s*,%s*%-2%s*,%s*"' .. sub .. '"%s*%)')
            local module = installs_submodule and (parent .. "." .. sub) or parent
            for array in
               fn.body:gmatch("luaL_register%s*%(%s*L%s*,%s*NULL%s*,%s*([%w_]+)%s*%)") do
               openers[#openers + 1] = {array = array, module = module, source = index}
            end
         end
      end
   end

   for _, site in ipairs(openers) do
      local names = array_names(sources[site.source], site.array)
      if names then
         for _, name in ipairs(names) do export(site.module, name) end
      end
   end

   return modules
end

--------------------------------------------------------------------------------
-- LuCI's own Lua modules

-- A module written in Lua rather than in C. Two ways to know which module a
-- file is, in this order:
--
--   1. it says so: `module "luci.util"`, `module("nixio.fs", function(m) ... end)`.
--      That is the library's own claim and it is the one to believe.
--   2. it does not, but it lives in a package's `luasrc/`: LuCI installs that
--      tree under LUA_LIBRARYDIR/luci keeping the directory structure as the
--      module name (luci.mk:98 and luci.mk:230), so `luasrc/sys.lua` is
--      `luci.sys` and `luasrc/model/uci.lua` is `luci.model.uci`.
--
-- Every .lua in the corpus is read, not just LuCI's, because the C and the Lua
-- halves of one library are not in one place: `nixio.fs` is a C table in fs.c
-- with `readfile` and `writefile` bolted on from a pure-Lua fs.lua shipped
-- beside it. Reading only the C half finds `nixio.fs.readfile` missing, which
-- would be a false alarm and would train a reader to ignore this spec.
--
-- A file that is neither -- a LuCI controller, a build script, a docsrc stub --
-- contributes nothing, and saying so is the point of the two rules rather than
-- guessing a module name out of a directory path.
--
-- A module-level name is one written at column 0, which is what makes it a
-- member of the module rather than a local or a nested function. The leading
-- "\n" is what makes the anchor mean "column 0": anchored to the whole subject
-- it would only ever match line one.
local function derive_lua_modules()
   local modules, tables, forwarded = {}, {}, {}

   local function export(module, name)
      modules[module] = modules[module] or {}
      modules[module][name] = true
   end
   local function is_table(module, name)
      tables[module] = tables[module] or {}
      tables[module][name] = true
   end
   local function is_forwarded(module, name)
      forwarded[module] = forwarded[module] or {}
      forwarded[module][name] = true
   end

   for _, path in ipairs(corpus_lua_files) do
      local source = slurp(path)
      if source then
         local module = source:match('module%s*%(?%s*"([%w_%.]+)"')
         if not module then
            local relative = path:match("luasrc/(.+)$")
            if relative then
               module = "luci." .. relative:gsub("%.lua$", ""):gsub("/", ".")
            end
         end
         if module then
            export(module, ".")
            local text = "\n" .. source
            for name in text:gmatch("\n([%w_]+)%s*=%s*{") do is_table(module, name) end
            for name in text:gmatch("\n([%w_]+)%s*=%s*setmetatable%s*%(") do is_table(module, name) end
            for name in text:gmatch("\nfunction%s+([%w_]+)%s*%(") do export(module, name) end
            for nested in text:gmatch("\nfunction%s+([%w_]+%.[%w_]+)%s*%(") do
               export(module, nested)
            end
            -- `context = setmetatable({}, {__index = ...})` is a table whose
            -- fields are whatever the metamethod returns.
            -- luci.dispatcher.context resolves to the request context that way,
            -- so its fields are real and unreadable from the source.
            for name in text:gmatch(
               "\n([%w_]+)%s*=%s*setmetatable%s*%(%s*{.-{%s*__index%s*=") do
               is_forwarded(module, name)
            end
         end
      end
   end

   return modules, tables, forwarded
end

--------------------------------------------------------------------------------
-- resolving a declared name against the corpus

-- What the corpus has to say about one declared pattern:
--   ok         the named function is exported
--   missing    the namespace is here and the function is not
--   unknown    the corpus implements no such namespace at all
--   wildcard   a glob rather than a name (ngx.re.*, *Handler)
local function resolve(pattern, modules, tables, forwarded)
   if pattern:find("%*") and not pattern:match("%.%*$") then
      return {verdict = "wildcard", pattern = pattern}
   end

   local base = pattern:gsub("%.%*$", "")
   local segments = {}
   for segment in base:gmatch("[^%.]+") do segments[#segments + 1] = segment end
   if #segments < 2 then
      return {verdict = "unknown", pattern = pattern, namespace = base}
   end

   for count = #segments, 1, -1 do
      local namespace = table.concat(segments, ".", 1, count)
      if modules[namespace] then
         if count == #segments then
            -- The whole name is a module: `luci.ip.*` names the luci.ip module
            -- and whatever hangs off it, and the corpus ships it.
            return {verdict = "ok", pattern = pattern, namespace = namespace}
         end
         local leaf = segments[count + 1]
         if tables[namespace] and tables[namespace][leaf]
               and forwarded[namespace] and forwarded[namespace][leaf] then
            return {verdict = "forwarded", pattern = pattern,
                    namespace = namespace, leaf = leaf}
         end
         if modules[namespace][leaf] then
            return {verdict = "ok", pattern = pattern, namespace = namespace, leaf = leaf}
         end
         return {verdict = "missing", pattern = pattern, namespace = namespace, leaf = leaf}
      end
   end

   return {verdict = "unknown", pattern = pattern, namespace = base}
end

-- Every dotted name every profile declares, with the profiles that declare it.
local function declared_patterns()
   local by_pattern, out = {}, {}
   local keys = {"sources", "sinks", "propagators", "shapes", "entry_points",
                 "store_writes", "store_reads", "validators"}
   for _, name in ipairs(profiles.builtin_names()) do
      local declaration = profiles.load_builtin(name)
      if declaration and not declaration.lua_standard then
         local function record(pattern)
            if pattern and pattern:find("%.") then
               if not by_pattern[pattern] then
                  by_pattern[pattern] = {}
                  out[#out + 1] = {pattern = pattern, profiles = by_pattern[pattern]}
               end
               local profiles_of = by_pattern[pattern]
               if not profiles_of[name] then
                  profiles_of[#profiles_of + 1] = name
                  profiles_of[name] = true
               end
            end
         end
         for _, key in ipairs(keys) do
            for _, entry in ipairs(declaration[key] or {}) do record(entry.pattern) end
         end
         for _, list in pairs(declaration.sanitizers or {}) do
            for _, pattern in ipairs(list) do record(pattern) end
         end
      end
   end
   table.sort(out, function(a, b) return a.pattern < b.pattern end)
   for _, entry in ipairs(out) do
      local names = {}
      for _, profile in ipairs(entry.profiles) do names[#names + 1] = profile end
      entry.profile = table.concat(names, "+")
   end
   return out
end

-- Every declaration, bucketed by what the corpus could say about it.
--
--   checked       the named function is exported
--   unexplained   the namespace is in the corpus and the function is not
--   unverifiable  the corpus implements no such namespace, or it is the Lua
--                 standard library, or the pattern is a glob
--   forwarded     the namespace is a table a runtime __index metamethod fills in
--
-- `unverifiable` is the bucket that must not disappear. A name lands there
-- because the corpus is silent about it -- cgilua, espressif, hisi, the
-- LuaJIT FFI, openresty, ubus, cjson, luaposix are all absent from it -- and a
-- reader who sees "spec passed" and nothing else has no way to tell those apart
-- from the ones that were checked. So they are printed, every run, by name.
local function check_every_declaration()
   local modules, tables, forwarded = derive_lua_modules()
   for module, names in pairs(derive_c_modules()) do
      modules[module] = modules[module] or {}
      for name in pairs(names) do modules[module][name] = true end
   end

   local result = {checked = 0, unexplained = {}, unverifiable = {}, forwarded = {}}
   for _, entry in ipairs(declared_patterns()) do
      local verdict = resolve(entry.pattern, modules, tables, forwarded)
      local bucket =
         (verdict.verdict == "ok") and result or
         (verdict.verdict == "missing" and not LUA_STANDARD[verdict.namespace])
            and result.unexplained or
         (verdict.verdict == "forwarded") and result.forwarded or
         result.unverifiable
      bucket[#bucket + 1] = entry.pattern
      if bucket == result then result.checked = result.checked + 1 end
   end
   for _, list in pairs(result) do
      if type(list) == "table" then table.sort(list) end
   end
   return result
end

-- A bucket that is not empty is a coverage limit somebody has to read, so it
-- goes to stdout in full. `make test` prints spec names, so this lands next to
-- them rather than in a log nobody opens, and it is not an assertion: these
-- names are wrong for a reason that has nothing to do with this code, and
-- failing on them would be the spec lying about what it is for.
local function report_unverifiable(result)
   if #result.unverifiable == 0 then return end
   io.write("  registry export check: ", #result.unverifiable,
      " declaration(s) the corpus cannot speak for, so they were NOT checked:\n    ")
   io.write(table.concat(result.unverifiable, " "), "\n")
   if #result.forwarded > 0 then
      io.write("  registry export check: ", #result.forwarded,
         " forwarded at runtime and NOT checked: ",
         table.concat(result.forwarded, " "), "\n")
   end
end

--------------------------------------------------------------------------------
-- the behaviour

describe("registry declarations name functions that exist", function()
   it("reports a request parameter reaching nixio.execp or nixio.exece", function()
      -- The behaviour half, here so this file is not only a data check: both
      -- take the command first (process.c:31 reads position 1 as the path and
      -- hands it to execvp or execve), so position 1 is the command.
      local api = require "luadoctor.api"
      for _, source in ipairs({
         'nixio.execp(luci.http.formvalue("cmd"))',
         'nixio.exece(luci.http.formvalue("cmd"), {})',
      }) do
         local report = api.check_source(source, {std = "+openwrt"})
         local reported = false
         for _, finding in ipairs(report) do
            if finding.code == "709" then reported = true end
         end
         assert_true(reported, source .. " reported nothing; the command is the first argument")
      end
   end)

   it("derives the corpus's exported names and finds no declaration that names a function which is not one", function()
      if not have_corpus then
         io.write("\n")
         io.write("  registry export check: SKIPPED - ", CORPUS, "/ is absent, so no name was derived.\n")
         io.write("  registry export check: SKIPPED - no declaration was compared with any implementation.\n")
         io.write("  registry export check: SKIPPED - this is not a pass. Run: make corpus && make test\n")
         return
      end

      local result = check_every_declaration()
      report_unverifiable(result)

      -- The derivation reading the whole corpus is the load-bearing part: a
      -- check that silently stopped looking is the failure mode this spec
      -- exists to prevent, so a clean run still has to prove it looked.
      assert_true(result.checked >= 15,
         ("the derivation checked only %d declarations out of a corpus with " ..
          "nixio, luci.ip and the whole LuCI Lua tree in it; the scan is " ..
          "broken rather than the registry clean"):format(result.checked))

      local unexplained = {}
      for _, pattern in ipairs(result.unexplained) do
         if not KNOWN_NOT_EXPORTED[pattern] then unexplained[#unexplained + 1] = pattern end
      end
      assert_equal(#unexplained, 0,
         "the registry declares " .. #unexplained .. " name(s) the corpus does not export:\n  "
         .. table.concat(unexplained, "\n  ")
         .. "\n  Each one is a sink that can never fire, or a source that can "
         .. "never taint. Fix the declaration, or record it in "
         .. "KNOWN_NOT_EXPORTED above with the reason it is still there.")

      -- And the reverse: the list of knowingly-wrong names is the review
      -- surface, so it has to keep matching what is actually declared.
      local declared = {}
      for _, pattern in ipairs(result.unexplained) do declared[pattern] = true end
      for pattern in pairs(KNOWN_NOT_EXPORTED) do
         assert_true(declared[pattern],
            "KNOWN_NOT_EXPORTED lists " .. pattern .. ", which the corpus now exports " ..
            "or the registry no longer declares; delete the entry")
      end
   end)

   it("lists every declaration the corpus cannot check, rather than passing over it", function()
      -- The same run, asserting the thing that was missing: the unverifiable
      -- names are a named list in the output, not a counter nobody reads. A
      -- green line next to seventy unchecked declarations is the shape of a
      -- false assurance, and this is what stops it being one.
      if not have_corpus then return end

      local result = check_every_declaration()
      assert_true(#result.unverifiable > 0,
         "nothing is unverifiable, which means either the corpus grew a copy of " ..
         "luaposix, openresty, cgilua and the rest, or the resolver stopped " ..
         "distinguishing 'no such namespace' from 'checked and fine'. Print the " ..
         "list before believing this.")

      -- And the ones that must be on it, by name. These are the namespaces the
      -- corpus genuinely does not ship, so if one ever stops being unverifiable
      -- the corpus has gained a library and the resolver should reach it.
      local listed = {}
      for _, pattern in ipairs(result.unverifiable) do listed[pattern] = true end
      for _, pattern in ipairs({"posix.exec", "posix.spawn", "ngx.exec", "ffi.load"}) do
         assert_true(listed[pattern],
            pattern .. " is expected to be unverifiable here (luaposix, openresty " ..
            "and the LuaJIT FFI are not in corpus/). If it is no longer on the " ..
            "list, the corpus has gained one of them and the spec should now be " ..
            "checking it rather than assuming.")
      end
   end)
end)
