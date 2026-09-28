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
}

-- Sources that arrive from embedded platforms; merged in by registry/stds/*.
local platform_sources = {}

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
   ngx = "ngx", ltn12 = "ltn12", luaposix = "posix",
}

-- Base counts, so a profile set can be rebuilt per analysis without leaking
-- declarations from a previous file into the next. Computed below, after the
-- tables it counts exist.
local base_counts = {sources = #default_sources, sinks = #default_sinks,
   propagators = #default_propagators, shapes = #default_shapes, sanitizers = {}}

function platform_api.reset()
   for i = #default_sinks, base_counts.sinks + 1, -1 do default_sinks[i] = nil end
   for i = #default_propagators, base_counts.propagators + 1, -1 do default_propagators[i] = nil end
   for i = #default_shapes, base_counts.shapes + 1, -1 do default_shapes[i] = nil end
   for i = #platform_sources, 0, -1 do platform_sources[i] = nil end
   for kind, set in pairs(sanitizers) do
      for pattern in pairs(set) do set[pattern] = nil end
   end
end

function platform_api.apply_profile(declaration)
   for _, source in ipairs(declaration.sources or {}) do
      platform_sources[#platform_sources + 1] = source
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
   platform_sources[#platform_sources + 1] = list
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

-- Find the first matching source declaration for a callee path.
function platform_api.match_source(path)
   return best_match(platform_sources, path) or best_match(default_sources, path)
end

function platform_api.match_sink(path)
   return best_match(default_sinks, path)
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

return platform_api
