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
   {pattern = "ffi.cdef", code = "707", kind = "ffi", arg = {1}},
   {pattern = "ffi.C.*", code = "707", kind = "ffi", arg = {}},
   {pattern = "require", code = "705", kind = "dyncode", arg = {1}},
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

function platform_api.reset()
   default_sources.sources = nil
   platform_sources.sources = nil
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
function platform_api.propagators() return default_propagators end

function platform_api.is_sanitizer(kind, path)
   local set = sanitizers[kind]
   if not set then return false end
   for pattern in pairs(set) do
      if util.wild_match(pattern, path) then return true end
   end
   return false
end

-- Find the first matching source declaration for a callee path.
function platform_api.match_source(path)
   for _, list in ipairs({default_sources, platform_sources}) do
      for _, source in ipairs(list) do
         if util.wild_match(source.pattern, path) then
            return source
         end
      end
   end
   return nil
end

function platform_api.match_sink(path)
   for _, sink in ipairs(default_sinks) do
      if util.wild_match(sink.pattern, path) then
         return sink
      end
   end
   return nil
end

function platform_api.match_propagator(path)
   for _, propagator in ipairs(default_propagators) do
      if util.wild_match(propagator.pattern, path) then
         return propagator
      end
   end
   return nil
end

return platform_api
