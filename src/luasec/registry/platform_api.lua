-- Platform API registry.
--
-- Everything the taint engine knows about platform functions lives here as data:
-- which calls introduce untrusted data (sources), which ones execute something
-- dangerous (sinks), which ones pass their argument's taint through to their
-- result (propagators), and which ones neutralize it for a given sink class
-- (sanitizers). Adding a platform is a data change, not a code change.
local util = require "luasec.util.util"

local platform_api = {}

-- Each entry:
--   pattern  dotted path, "*" and "?" wildcards, ":" for method calls
--   id       stable identifier reported as the source name
--   name     human description
--   confidence default confidence of findings sourced here
local default_sources = {
   {pattern = "http.formvalue", id = "http.formvalue", name = "HTTP request parameter", confidence = "certain"},
   {pattern = "http.formvalue.*", id = "http.formvalue", name = "HTTP request parameter", confidence = "certain"},
   {pattern = "luci.http.formvalue", id = "luci.http.formvalue", name = "LuCI request parameter", confidence = "certain"},
   {pattern = "luci.http.formvalue.*", id = "luci.http.formvalue", name = "LuCI request parameter", confidence = "certain"},
   {pattern = "os.getenv", id = "os.getenv", name = "process environment", confidence = "medium"},
   {pattern = "os.getenv.*", id = "os.getenv", name = "process environment", confidence = "medium"},
   {pattern = "io.input", id = "io.input", name = "interactive input", confidence = "medium"},
   {pattern = "io.lines", id = "io.lines", name = "file contents", confidence = "medium"},
   {pattern = "io.open:read", id = "io.open:read", name = "file contents", confidence = "medium"},
   {pattern = "file:read", id = "file:read", name = "file contents", confidence = "medium"},
   {pattern = "json.decode", id = "json.decode", name = "decoded document", confidence = "high"},
   {pattern = "jsonc.parse", id = "jsonc.parse", name = "decoded document", confidence = "high"},
   {pattern = "cjson.decode", id = "cjson.decode", name = "decoded document", confidence = "high"},
}

-- Method calls the taint engine must see as sources.
--
-- The object is whatever the script called it: `handle`, `fh`, `f`, `self`. Only
-- the method name is stable, and `handle:read("*a")` returns a file's contents
-- whoever the handle is. Matched at medium confidence for that reason.
local default_method_sources = {
   {pattern = "read", id = "file:read", name = "file contents", confidence = "medium"},
   {pattern = "readline", id = "file:read", name = "file contents", confidence = "medium"},
   {pattern = "readall", id = "file:read", name = "file contents", confidence = "medium"},
}

-- Sources that arrive from embedded platforms; merged in by registry/stds/*.
local platform_sources = {}

-- Functions a profile declares as called with request data: their named
-- arguments are tainted at entry. Merged in by profiles; cleared by reset().
local entry_points = {}

-- Calls that write a value to a store (a configuration database) and calls that
-- read one back, so a value written from request data and read back into a
-- command is seen as one flow (729). Merged in by profiles; cleared by reset().
local store_writes = {}
local store_reads = {}

-- Functions that validate their argument (an IP/hostname/number check used as a
-- guard): a value they are called on reaches a sink as a guarded finding, one
-- confidence step lower and named, rather than at full confidence.
local validators = {}

-- Globals whose read is itself untrusted input (CGILua `cgi`); merged in by
-- registry/stds/*. Exact name match, never a local of the same name.
local global_sources = {}

-- Sinks that execute a command. `arg` lists which argument indices matter.
local default_sinks = {
   {pattern = "os.execute", code = "701", kind = "exec", arg = {1}},
   {pattern = "os.execute.*", code = "701", kind = "exec", arg = {1}},
   {pattern = "io.popen", code = "702", kind = "exec", arg = {1}},
   {pattern = "io.popen.*", code = "702", kind = "exec", arg = {1}},
   {pattern = "loadstring", code = "703", kind = "dyncode", arg = {1}},
   {pattern = "load", code = "703", kind = "dyncode", arg = {1}},
   {pattern = "dofile", code = "704", kind = "dyncode", arg = {1}},
   {pattern = "loadfile", code = "704", kind = "dyncode", arg = {1}},
   {pattern = "package.loadlib", code = "706", kind = "dyncode", arg = {1}},
   {pattern = "package.loadlib.*", code = "706", kind = "dyncode", arg = {1}},
   {pattern = "ffi.load", code = "706", kind = "dyncode", arg = {1}},
}

-- API shapes worth reporting on their own, independent of taint and of any
-- more specific sink entry. Using the FFI at all is a finding, whether or not
-- its argument is attacker controlled.
local default_shapes = {
   {pattern = "ffi.cdef", code = "707", name = "ffi.cdef"},
   {pattern = "ffi.C.*", code = "707", name = "ffi.C"},
   {pattern = "ffi.load", code = "706", name = "ffi.load"},
   {pattern = "package.loadlib", code = "706", name = "package.loadlib"},
   {pattern = "package.loadlib.*", code = "706", name = "package.loadlib"},
   {pattern = "require", code = "705", name = "require"},
}

-- Calls whose result carries the taint of their arguments.
local default_propagators = {
   {pattern = "tostring", arg = {1}},
   {pattern = "string.*", arg = {1}},
   {pattern = "table.concat", arg = {1}},
   {pattern = "table.unpack", arg = {1}},
   {pattern = "unpack", arg = {1}},
   {pattern = "ipairs", arg = {1}},
   {pattern = "pairs", arg = {1}},
   {pattern = "string.format", arg = {1, 2}},
   {pattern = "ngx.re.gsub", arg = {1}},
   {pattern = "ngx.re.find", arg = {1}},
}

-- Sanitizers, matched per sink kind. A shell quoting helper must not silence a
-- dynamic-code sink, which is why these are keyed by kind rather than global.
local sanitizers = {
   shell = {},
   dyncode = {},
   path = {},
}

-- What a module is called once required. `local C = require("ffi").C` is the
-- shape every LuaJIT binding uses, and without this the callee path stops at
-- "C". A profile extends the table.
local module_names = {
   ffi = "ffi", posix = "posix", nixio = "nixio", cjson = "cjson",
   json = "json", jsonc = "jsonc", luci = "luci", uci = "uci",
   ["luci.json"] = "json", ["luci.jsonc"] = "jsonc", ["luci.util"] = "luci.util",
   ngx = "ngx", ltn12 = "ltn12", luaposix = "posix",
}

-- Base counts, so a profile set can be rebuilt per analysis without leaking
-- declarations from a previous file into the next. Computed below, after the
-- tables it counts exist.
-- Filled in at the bottom, once every table exists: this is the base a profile
-- set is restored to, so a previous analysis cannot leak into the next.
local base_counts = {sanitizers = {}}

function platform_api.reset()
   for i = #default_sinks, base_counts.sinks + 1, -1 do default_sinks[i] = nil end
   for i = #default_propagators, base_counts.propagators + 1, -1 do default_propagators[i] = nil end
   for i = #default_method_sources, base_counts.method_sources + 1, -1 do default_method_sources[i] = nil end
   for i = #default_shapes, base_counts.shapes + 1, -1 do default_shapes[i] = nil end
   for i = #platform_sources, 0, -1 do platform_sources[i] = nil end
   for i = #global_sources, 0, -1 do global_sources[i] = nil end
   for i = #entry_points, 0, -1 do entry_points[i] = nil end
   for i = #store_writes, 0, -1 do store_writes[i] = nil end
   for i = #store_reads, 0, -1 do store_reads[i] = nil end
   for i = #validators, 0, -1 do validators[i] = nil end
   for kind, set in pairs(sanitizers) do
      for pattern in pairs(set) do set[pattern] = nil end
   end
end

function platform_api.apply_profile(declaration)
   for _, source in ipairs(declaration.sources or {}) do
      platform_sources[#platform_sources + 1] = source
   end
   for _, source in ipairs(declaration.method_sources or {}) do
      default_method_sources[#default_method_sources + 1] = source
   end
   for _, source in ipairs(declaration.global_sources or {}) do
      global_sources[#global_sources + 1] = source
   end
   for _, entry in ipairs(declaration.entry_points or {}) do
      entry_points[#entry_points + 1] = entry
   end
   for _, entry in ipairs(declaration.store_writes or {}) do
      store_writes[#store_writes + 1] = entry
   end
   for _, entry in ipairs(declaration.store_reads or {}) do
      store_reads[#store_reads + 1] = entry
   end
   for _, entry in ipairs(declaration.validators or {}) do
      validators[#validators + 1] = entry
   end
   for _, sink in ipairs(declaration.sinks or {}) do
      default_sinks[#default_sinks + 1] = sink
   end
   for _, propagator in ipairs(declaration.propagators or {}) do
      default_propagators[#default_propagators + 1] = propagator
   end
   for _, shape in ipairs(declaration.shapes or {}) do
      default_shapes[#default_shapes + 1] = shape
   end
   platform_api.add_modules(declaration.modules)
   for kind, list in pairs(declaration.sanitizers or {}) do
      for _, pattern in ipairs(list) do
         sanitizers[kind] = sanitizers[kind] or {}
         sanitizers[kind][pattern] = true
      end
   end
end

-- Merge user- or platform-supplied declarations into the live tables.
function platform_api.add_sources(list)
   -- Each entry, not the list. Appending the list put a nested table where the
   -- matcher expects a declaration, so `entry.pattern` was nil and a declared
   -- source raised "attempt to get length of a nil value" out of the public
   -- entry point rather than being matched. The other two add_* functions below
   -- already did this; this one did not, and there was no test for it because
   -- nothing in the suite declares a source through the options table.
   for _, entry in ipairs(list or {}) do
      platform_sources[#platform_sources + 1] = entry
   end
end

function platform_api.add_sinks(list)
   for _, sink in ipairs(list or {}) do
      default_sinks[#default_sinks + 1] = sink
   end
end

function platform_api.add_propagators(list)
   for _, propagator in ipairs(list or {}) do
      default_propagators[#default_propagators + 1] = propagator
   end
end

function platform_api.add_sanitizers(kind, list)
   for _, pattern in ipairs(list or {}) do
      sanitizers[kind][pattern] = true
   end
end

function platform_api.sources() return default_sources end
function platform_api.platform_sources() return platform_sources end
function platform_api.sinks() return default_sinks end
function platform_api.shapes() return default_shapes end

function platform_api.propagators() return default_propagators end

--- Name of a module once required, or nil when unknown.
function platform_api.module_name(name)
   return module_names[name]
end

function platform_api.add_modules(map)
   for name, alias in pairs(map or {}) do
      module_names[name] = alias
   end
end

function platform_api.is_sanitizer(kind, path)
   local set = sanitizers[kind]
   if not set then return false end
   for pattern in pairs(set) do
      if util.wild_match(pattern, path) then return true end
   end
   return false
end

-- Most specific match wins: fewer wildcards first, then a longer pattern. Without
-- this, a generic `ffi.C.*` declared in the base set would shadow a specific
-- `ffi.C.system` coming from a platform profile.
local function specificity(entry)
   local wildcards = 0
   for _ in entry.pattern:gmatch("[%*%?]") do wildcards = wildcards + 1 end
   return wildcards, -#entry.pattern
end

local function best_match(list, path)
   local best
   for _, entry in ipairs(list) do
      if util.wild_match(entry.pattern, path) then
         if not best or specificity(entry) < specificity(best) then
            best = entry
         end
      end
   end
   return best
end

-- best_match restricted by a predicate on the entry. A sink declares which
-- position it is matched in: `kind = "assign"` entries are targets and every
-- other kind is a callee, so the two can share one declaration list without
-- either matcher being able to return the other's entries.
local function best_match_where(list, path, accepts)
   local best
   for _, entry in ipairs(list) do
      if accepts(entry) and util.wild_match(entry.pattern, path) then
         if not best or specificity(entry) < specificity(best) then
            best = entry
         end
      end
   end
   return best
end

-- Find the first matching source declaration for a callee path.
function platform_api.match_source(path)
   return best_match(platform_sources, path) or best_match(default_sources, path)
end

-- Same, for a method call. The engine passes the method name when the object
-- cannot be named, because `handle:read("*a")` is a file read whoever the handle
-- is.
function platform_api.match_method_source(method)
   return best_match(default_method_sources, method)
end

-- The entry-point declaration a function name matches, or nil. The caller tries
-- the full name and then the short name after the last `.` or `:`. An entry with
-- a `file` glob applies only to functions in a file whose path matches it, so it
-- never matches source that has no path (check_source).
-- Fold `.` and `..` segments out of a path, textually, before a `file` glob sees it. A path
-- the walker produced has none; one a caller or a test assembled can, and
-- `controller/../x.lua` must be judged by where it resolves, not by the text it contains.
local function normalise_path(path)
   local out = {}
   for segment in path:gmatch("[^/]+") do
      if segment == ".." then
         out[#out] = nil
      elseif segment ~= "." then
         out[#out + 1] = segment
      end
   end
   return (path:sub(1, 1) == "/" and "/" or "") .. table.concat(out, "/")
end

function platform_api.match_entry_point(name, path)
   -- A file-scoped entry whose glob matches is more specific than a global one
   -- and wins: it is how two profiles for the same handler-name convention in
   -- different files (a web `*Handler` and an ACS `*DiagnosticsHandler` in the
   -- TR-069 libraries) are told apart. Within one scope, pattern specificity
   -- decides as usual.
   local scoped, global = {}, {}
   for _, entry in ipairs(entry_points) do
      if entry.file == nil then
         global[#global + 1] = entry
      elseif path and util.wild_match(entry.file, normalise_path(path)) then
         scoped[#scoped + 1] = entry
      end
   end
   return best_match(scoped, name) or best_match(global, name)
end

-- The store write or store read a callee path matches, or nil.
function platform_api.match_store_write(path)
   return best_match(store_writes, path)
end

function platform_api.match_store_read(path)
   return best_match(store_reads, path)
end

function platform_api.match_validator(path)
   return best_match(validators, path)
end

-- A global read is a source only on an exact name match.
function platform_api.match_global_source(name)
   for _, entry in ipairs(global_sources) do
      if entry.global == name then return entry end
   end
   return nil
end

-- An entry with no `kind` is a callee, which is what `check_sink` has always
-- matched. An `assign` entry declares a target and is not a callee, so it is
-- excluded here and not only in match_assign_sink: that keeps `ngx.header` from
-- ever being returned for a call, and it is what makes call matching provably
-- unchanged by the presence of an assignment sink.
local function is_callee_sink(entry)
   return (entry.kind or "shell") ~= "assign"
end

function platform_api.match_sink(path)
   return best_match_where(default_sinks, path, is_callee_sink)
end

-- The assignment-shaped sink a target's base path matches, or nil. Kept
-- deliberately separate from match_sink: the two answer different questions
-- (is this expression called, or written to) and sharing one matcher is how a
-- target would end up being matched as a callee.
function platform_api.match_assign_sink(path)
   return best_match_where(default_sinks, path,
      function(entry) return entry.kind == "assign" end)
end

function platform_api.match_propagator(path)
   return best_match(default_propagators, path)
end

function platform_api.add_shapes(list)
   for _, shape in ipairs(list or {}) do
      default_shapes[#default_shapes + 1] = shape
   end
end

function platform_api.match_shape(path)
   return best_match(default_shapes, path)
end


base_counts.sources = #default_sources
base_counts.sinks = #default_sinks
base_counts.propagators = #default_propagators
base_counts.shapes = #default_shapes
base_counts.method_sources = #default_method_sources

return platform_api
