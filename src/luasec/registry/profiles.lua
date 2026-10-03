-- Platform profiles.
--
-- A profile is a data file returning a declaration:
--   {name = "openwrt",
--    sources = {{pattern = "uci.get", id = "uci.get", name = "OpenWrt UCI value", confidence = "high"}},
--    sinks = {{pattern = "luci.sys.call", code = "701", kind = "exec", arg = {1}}},
--    propagators = {{pattern = "luci.util.pcdata", arg = {1}}},
--    sanitizers = {shell = {"luci.util.shellquote"}, dyncode = {}, path = {}}}
--
-- `luasec --std +openwrt+luci` composes profiles. `--rules file.lua` loads the
-- same shape from anywhere, which is how a vendor documents their own API.
local util = require "luasec.util.util"
local builtin_standards = require "luacheck.builtin_standards"

local profiles = {}

local builtin = {
   openwrt = "luasec.registry.stds.openwrt",
   luci = "luasec.registry.stds.luci",
   cgilua = "luasec.registry.stds.cgilua",
   luajit = "luasec.registry.stds.luajit",
   openresty = "luasec.registry.stds.openresty",
   hisi = "luasec.registry.stds.hisi",
   espressif = "luasec.registry.stds.espressif",
}

local function validate(name, declaration)
   assert(type(declaration) == "table", "profile " .. name .. " must return a table")
   for _, key in ipairs({"sources", "sinks", "propagators", "shapes", "entry_points",
         "store_writes", "store_reads"}) do
      if declaration[key] ~= nil then
         assert(type(declaration[key]) == "table", "profile " .. name .. "." .. key .. " must be a list")
         for _, entry in ipairs(declaration[key]) do
            assert(type(entry) == "table",
               "every " .. name .. "." .. key .. " entry must be a table, got "
                  .. type(entry))
            assert(type(entry.pattern) == "string",
               "every " .. name .. "." .. key .. " entry needs a pattern")
         end
      end
   end
   if declaration.modules ~= nil then
      assert(type(declaration.modules) == "table", "profile " .. name .. ".modules must be a table")
   end
   if declaration.global_sources ~= nil then
      assert(type(declaration.global_sources) == "table", "profile " .. name .. ".global_sources must be a list")
      for _, entry in ipairs(declaration.global_sources) do
         assert(type(entry) == "table",
            "every " .. name .. ".global_sources entry must be a table, got "
               .. type(entry))
         assert(type(entry.global) == "string",
            "every " .. name .. ".global_sources entry needs a global")
      end
   end
   for kind, list in pairs(declaration.sanitizers or {}) do
      assert(type(list) == "table", "profile " .. name .. ".sanitizers." .. kind .. " must be a list")
   end

   -- The fields that decide what a declaration DOES, not just that it is there.
   -- A sink with `code = 701` (a number) or `arg = "1"` (a string) passed
   -- validation and then did nothing: the run came back clean with exit 0 on a
   -- file doing exactly what the profile said to flag. --rules is documented as
   -- how a vendor describes their own API, so a declaration that loads and does
   -- nothing is the worst way for it to fail - a JSON habit, `"1"` for `{1}`,
   -- silently removes a declared sink.
   -- A store write names where its value goes (`table`, `column`) and what it
   -- writes (`value`, or a whole `row`); a store read names where it reads
   -- from. Every one is an argument position, and a write writes exactly one
   -- of the two shapes.
   for _, key in ipairs({"store_writes", "store_reads"}) do
      for _, entry in ipairs(declaration[key] or {}) do
         for _, field in ipairs({"table", "column", "value", "row"}) do
            local position = entry[field]
            assert(position == nil or (type(position) == "number" and position >= 1 and position % 1 == 0),
               "every " .. name .. "." .. key .. " entry needs " .. field .. " as an argument position")
         end
         assert(entry.store == nil or type(entry.store) == "string",
            "every " .. name .. "." .. key .. " entry needs store as a string")
         if key == "store_writes" then
            assert((entry.value ~= nil) ~= (entry.row ~= nil),
               "every " .. name .. ".store_writes entry needs exactly one of value or row")
         else
            assert(entry.value == nil and entry.row == nil,
               "a " .. name .. ".store_reads entry reads; it has no value or row")
         end
      end
   end

   for _, key in ipairs({"sources", "sinks", "propagators", "shapes", "entry_points"}) do
      for _, entry in ipairs(declaration[key] or {}) do
         if entry.code ~= nil then
            assert(type(entry.code) == "string",
               "every " .. name .. "." .. key .. " entry needs code as a string, got "
                  .. type(entry.code))
         end
         if entry.arg ~= nil then
            assert(type(entry.arg) == "table",
               "every " .. name .. "." .. key .. " entry needs arg as a list of positions")
            for _, position in ipairs(entry.arg) do
               assert(type(position) == "number",
                  "every " .. name .. "." .. key .. " arg entry must be a number")
            end
         end
         if key == "entry_points" and entry.file ~= nil then
            assert(type(entry.file) == "string",
               "every " .. name .. ".entry_points entry needs file as a path glob string")
         end
         if entry.channel ~= nil then
            assert(type(entry.channel) == "string",
               "every " .. name .. "." .. key .. " entry needs channel as a string")
         end
         if entry.confidence ~= nil then
            assert(type(entry.confidence) == "string",
               "every " .. name .. "." .. key .. " entry needs confidence as a string")
         end
         if entry.filters ~= nil then
            assert(type(entry.filters) == "table",
               "every " .. name .. "." .. key .. " entry needs filters as a table of position to string")
            local positions = {}
            for _, position in ipairs(entry.arg or {}) do positions[position] = true end
            for position, chars in pairs(entry.filters) do
               assert(type(position) == "number" and type(chars) == "string",
                  "every " .. name .. "." .. key .. " filters entry maps a position number to a string")
               assert(positions[position],
                  "every " .. name .. "." .. key .. " filters position must also be in arg")
            end
         end
      end
   end

   return declaration
end

--- Names of the built-in profiles, sorted.
function profiles.builtin_names()
   local names = {}
   for name in pairs(builtin) do names[#names + 1] = name end
   table.sort(names)
   return names
end

--- Is this a luacheck Lua standard (`lua51`, `luajit`, `min`, `max`, ...)?
-- Accepted so `--std lua51` means the Lua standard rather than an error, which is
-- what makes 903, the dialect-mismatch finding, expressible.
function profiles.is_lua_standard(name)
   return builtin_standards[name] ~= nil and builtin[name] == nil
end

--- Is this name a platform profile rather than a Lua standard? Some names are
-- both (`luajit`), and a profile is the more specific claim.
function profiles.is_platform(name)
   return builtin[name] ~= nil
end

--- Does a `--std` value name one or more Lua standards explicitly?
-- `lua51`, `+lua51`, `lua51+openwrt` all do; `+openwrt` and an absent value do not.
function profiles.is_lua_standard_spec(spec)
   if not spec or spec == "" then return false end
   for part in spec:gmatch("[^+]+") do
      if profiles.is_lua_standard(util.trim(part)) then return true end
   end
   return false
end

--- Load one built-in profile by name.
function profiles.load_builtin(name)
   if profiles.is_lua_standard(name) then
      -- A Lua standard, not a platform profile: it declares no security meaning.
      return {name = name, lua_standard = true}
   end

   local module = builtin[name]
   if not module then
      return nil, ("unknown platform profile '%s' (known: %s)"):format(
         name, table.concat(profiles.known_names(), ", "))
   end
   -- luasec: ignore 705  the module name comes from the shipped profile list, not from input
   return validate(name, require(module))
end

--- Every name `--std` accepts, platform profiles and Lua standards.
function profiles.known_names()
   local names = profiles.builtin_names()
   for name in pairs(builtin_standards) do
      names[#names + 1] = name
   end
   table.sort(names)
   return names
end

--- Load a profile from a Lua file returning a declaration table.
function profiles.load_file(path)
   -- luasec: ignore 704  the profile path comes from the operator's --rules flag, not from request data
   local chunk, load_error = loadfile(path)
   if not chunk then
      return nil, ("cannot load profile %s: %s"):format(path, tostring(load_error))
   end
   local ok, declaration = pcall(chunk)
   if not ok then
      return nil, ("profile %s errored: %s"):format(path, tostring(declaration))
   end

   -- validate() reports a malformed profile with assert(), so it has to be
   -- inside a pcall like the chunk is. Outside it, a profile that loads and is
   -- then rejected - one that returns a number, one with a sink entry that has
   -- no pattern - raised out of the CLI as a Lua traceback and exited 1, which
   -- this tool defines as "findings". A CI reading that as findings shows a
   -- config error as a report; a missing file correctly exits 2, and a
   -- malformed one must not exit 1.
   local valid, problem = pcall(validate, path, declaration)
   if not valid then
      -- assert() prefixes its message with the source location. The operator
      -- wrote the profile, not the validator, so the location is noise.
      local message = tostring(problem):gsub("^[^:]*:%d+: ", "")
      return nil, ("profile %s is not valid: %s"):format(path, message)
   end
   return problem
end

--- Split a --std value into profile names. A leading "+" or an empty first part
-- means "add to the defaults" rather than "use only these".
function profiles.split(spec)
   local names, add = {}, true
   if spec:match("^%+") then
      spec = spec:sub(2)
   elseif spec:sub(1, 1) ~= "+" and spec:find("+", 1, true) then
      add = false
   end

   for part in spec:gmatch("[^+]+") do
      names[#names + 1] = util.trim(part)
   end

   return names, add
end

return profiles
