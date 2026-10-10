-- `lua-doctor rules`: the rule catalogue from the command line. `list` prints one
-- line per code and `explain` prints a code's doc page. The pages live in
-- docs/rules/ beside the installation, the same files the repository renders.
local api = require "luasec.api"
local codes = require "luasec.rules.codes"
local config = require "luasec.cli.config"

local rules_cmd = {}

local function pad(text, width)
   text = tostring(text or "")
   return text .. string.rep(" ", width - #text)
end

local function list(out)
   for _, rule in ipairs(api.rule_catalogue()) do
      out:write(rule.code, "  ", pad(rule.category, 8), "  ", pad(rule.severity, 8), "  ",
         pad(rule.cwe, 7), "  ", codes.meaning(rule.code), "\n")
   end
   return 0
end

local function explain(code, root, out, err)
   if not code then
      err:write("lua-doctor: rules explain needs a code\n")
      return 2
   end
   local known = false
   for _, rule in ipairs(api.rule_catalogue()) do
      if rule.code == code then known = true end
   end
   if not known then
      err:write(("lua-doctor: unknown code '%s': run 'lua-doctor rules list' to see them\n"):format(code))
      return 2
   end
   local path = root .. "/docs/rules/" .. code .. ".md"
   local handle, open_error = io.open(path, "rb")
   if not handle then
      err:write("lua-doctor: cannot read " .. path .. ": " .. tostring(open_error) .. "\n")
      return 2
   end
   out:write(handle:read("*a"))
   handle:close()
   return 0
end

local SEVERITIES = {off = true, low = true, medium = true, high = true, critical = true}

local function config_path(rest)
   local path = config.DEFAULT_NAME
   local index = 1
   while index <= #rest do
      local token = rest[index]
      if token == "--config" then
         if not rest[index + 1] then return nil end
         path = rest[index + 1]
         index = index + 2
      elseif token:match("^%-%-config=") then
         path = token:match("^%-%-config=(.*)$")
         index = index + 1
      else
         index = index + 1
      end
   end
   return path
end

local function tune(argv, command, _root, out, err)
   local code = argv[2]
   local need = command == "set" and "lua-doctor: rules set needs a code and a severity\n"
      or ("lua-doctor: rules " .. command .. " needs a code\n")
   if command == "set" and (not argv[2] or not argv[3]) then
      err:write(need)
      return 2
   end
   if command ~= "set" and not argv[2] then
      err:write(need)
      return 2
   end
   local severity = argv[3]
   if command == "set" and not SEVERITIES[severity] then
      err:write("lua-doctor: expected off, low, medium, high or critical\n")
      return 2
   end
   if not codes.exists(tostring(code)) then
      err:write(("lua-doctor: unknown code '%s': run 'lua-doctor rules list' to see them\n"):format(code))
      return 2
   end
   local rest = {}
   local first = command == "set" and 4 or 3
   for index = first, #argv do rest[#rest + 1] = argv[index] end
   local path = config_path(rest)
   if not path then
      err:write("lua-doctor: --config needs a value\n")
      return 2
   end
   local hint
   if command == "enable" then
      hint = ("remove %q from disable and severity,"):format(code)
   elseif command == "disable" or severity == "off" then
      hint = ("disable = {%q},"):format(code)
   else
      hint = ("severity = {[%q] = %q},"):format(code, severity)
   end
   local probe = io.open(path, "rb")
   if probe then
      local text = probe:read("*a")
      probe:close()
      if text and text:find("--", 1, true) then
         err:write(("lua-doctor: %s has comments that a rewrite would lose; add this by hand instead: %s\n")
            :format(path, hint))
         return 2
      end
   end
   local value = {}
   do
      local exists = io.open(path, "rb")
      if exists then
         exists:close()
         local loaded, load_error = config.load(path)
         if not loaded then
            err:write("lua-doctor: " .. tostring(load_error) .. "\n")
            return 2
         end
         value = loaded
      end
   end
   local result
   if command == "enable" then
      local kept = {}
      for _, pattern in ipairs(value.disable or {}) do
         if pattern ~= code then kept[#kept + 1] = pattern end
      end
      value.disable = kept
      if value.severity then value.severity[code] = nil end
      result = "default"
   elseif command == "disable" or severity == "off" then
      value.disable = value.disable or {}
      local found = false
      for _, pattern in ipairs(value.disable) do
         if pattern == code then found = true break end
      end
      if not found then value.disable[#value.disable + 1] = code end
      result = "off"
   else
      value.severity = value.severity or {}
      value.severity[code] = severity
      local kept = {}
      for _, pattern in ipairs(value.disable or {}) do
         if pattern ~= code then kept[#kept + 1] = pattern end
      end
      value.disable = kept
      result = severity
   end
   local handle, open_error = io.open(path, "wb")
   if not handle then
      err:write("lua-doctor: cannot write " .. path .. ": " .. tostring(open_error) .. "\n")
      return 2
   end
   handle:write(config.serialize(value))
   handle:close()
   out:write(("wrote %s: %s -> %s\n"):format(path, code, result))
   return 0
end

--- Run `lua-doctor rules <argv...>`. `argv` is what follows `rules`; `root` is the
-- installation directory. Returns the exit code.
function rules_cmd.run(argv, root, out, err)
   out, err = out or io.stdout, err or io.stderr
   local command = argv[1] or "list"
   if command == "list" then return list(out) end
   if command == "explain" then return explain(argv[2], root, out, err) end
   if command == "set" then return tune(argv, "set", root, out, err) end
   if command == "disable" then return tune(argv, "disable", root, out, err) end
   if command == "enable" then return tune(argv, "enable", root, out, err) end
   err:write(("lua-doctor: unknown rules command '%s': expected list, explain, set, enable or disable\n")
      :format(command))
   return 2
end

return rules_cmd
