-- The project config file, luasec.config.lua: a Lua table kept beside the code.
-- It is loaded as text in an empty environment, so it can hold data and nothing
-- else. Every key and value is checked: a config typo that is ignored is a gate
-- that is quietly off, so anything this module does not know stops the run.
local codes = require "luasec.rules.codes"

local config = {}

config.DEFAULT_NAME = "luasec.config.lua"

local KEYS = {"allow", "disable", "fail_on", "severity", "std"}
local ALLOW_KEYS = {code = true, file = true, reason = true}
local SEVERITIES = {low = true, medium = true, high = true, critical = true}
local SEVERITY_LIST = "low, medium, high, critical"

--- Check a loaded config table. Returns it, or nil plus a message.
function config.check(value, path)
   local function bad(message)
      return nil, ("cannot use config %s: %s"):format(path, message)
   end
   local known = {}
   for _, key in ipairs(KEYS) do known[key] = true end
   for key in pairs(value) do
      if not known[key] then
         return bad(("unknown key '%s': expected %s"):format(tostring(key), table.concat(KEYS, ", ")))
      end
   end
   if value.std ~= nil and type(value.std) ~= "string" then
      return bad("std must be a string such as '+openwrt+luci'")
   end
   if value.fail_on ~= nil and not SEVERITIES[value.fail_on] then
      return bad("fail_on must be one of " .. SEVERITY_LIST)
   end
   if value.disable ~= nil then
      if type(value.disable) ~= "table" then return bad("disable must be a list of code patterns") end
      for index, pattern in ipairs(value.disable) do
         if type(pattern) ~= "string" then return bad(("disable[%d] must be a string"):format(index)) end
      end
   end
   if value.severity ~= nil then
      if type(value.severity) ~= "table" then return bad("severity must map a code to a severity") end
      for code, severity in pairs(value.severity) do
         if not codes.exists(tostring(code)) then
            return bad(("severity: '%s' is not a luasec code"):format(tostring(code)))
         end
         if not SEVERITIES[severity] then
            return bad(("severity['%s'] must be one of %s"):format(tostring(code), SEVERITY_LIST))
         end
      end
   end
   if value.allow ~= nil then
      if type(value.allow) ~= "table" then return bad("allow must be a list of {code, file, reason}") end
      for index, entry in ipairs(value.allow) do
         if type(entry) ~= "table" then return bad(("allow[%d] must be a table"):format(index)) end
         for key in pairs(entry) do
            if not ALLOW_KEYS[key] then
               return bad(("allow[%d]: unknown key '%s': expected code, file, reason"):format(index, tostring(key)))
            end
         end
         if type(entry.code) ~= "string" or not codes.exists(entry.code) then
            return bad(("allow[%d]: '%s' is not a luasec code"):format(index, tostring(entry.code)))
         end
         if entry.file ~= nil and type(entry.file) ~= "string" then
            return bad(("allow[%d].file must be a string"):format(index))
         end
         if type(entry.reason) ~= "string" or not entry.reason:match("%S") then
            return bad(("allow[%d] needs a reason"):format(index))
         end
      end
   end
   return value
end

--- Load and check a config file. Returns the table, or nil plus a message.
function config.load(path)
   local handle, open_error = io.open(path, "rb")
   if not handle then
      return nil, "cannot read config " .. path .. ": " .. tostring(open_error)
   end
   local text = handle:read("*a")
   handle:close()
   -- luasec: ignore 710  the config text is the operator's own file, loaded as data in an empty environment
   local chunk, parse_error = load(text, "@" .. path, "t", {})
   if not chunk then return nil, "cannot use config " .. path .. ": " .. tostring(parse_error) end
   local ok, value = pcall(chunk)
   if not ok then return nil, "cannot use config " .. path .. ": " .. tostring(value) end
   if type(value) ~= "table" then
      return nil, "cannot use config " .. path .. ": it must return a table"
   end
   return config.check(value, path)
end

--- Whether an allow entry covers a finding.
function config.allows(entry, finding)
   if finding.code ~= entry.code then return false end
   if entry.file == nil then return true end
   local file = finding.file or ""
   return file == entry.file or file:sub(-(#entry.file + 1)) == "/" .. entry.file
end

--- Apply the allow list: return the findings it does not cover, and write one
-- line per entry to stderr saying what it removed, so nothing is silenced
-- without a trace.
function config.apply_allow(findings, allow)
   if not allow or #allow == 0 then return findings end
   local counts, kept = {}, {}
   for _, finding in ipairs(findings) do
      local covered = false
      for index, entry in ipairs(allow) do
         if config.allows(entry, finding) then
            counts[index] = (counts[index] or 0) + 1
            covered = true
            break
         end
      end
      if not covered then kept[#kept + 1] = finding end
   end
   for index, entry in ipairs(allow) do
      local where = entry.file or "any file"
      if counts[index] then
         io.stderr:write(("luasec: allowed %d finding(s) of %s in %s: %s\n")
            :format(counts[index], entry.code, where, entry.reason))
      else
         io.stderr:write(("luasec: config allow for %s in %s matched nothing\n")
            :format(entry.code, where))
      end
   end
   return kept
end

return config
