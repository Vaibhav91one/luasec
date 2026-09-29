-- `luasec rules`: the rule catalogue from the command line. `list` prints one
-- line per code and `explain` prints a code's doc page. The pages live in
-- docs/rules/ beside the installation, the same files the repository renders.
local api = require "luasec.api"

local rules_cmd = {}

local function meaning(message)
   return (message:gsub("%s*%({%w+}%)", ""):gsub("%s*{%w+}", ""))
end

local function pad(text, width)
   text = tostring(text or "")
   return text .. string.rep(" ", width - #text)
end

local function list(out)
   for _, rule in ipairs(api.rule_catalogue()) do
      out:write(rule.code, "  ", pad(rule.category, 8), "  ", pad(rule.severity, 8), "  ",
         pad(rule.cwe, 7), "  ", meaning(rule.message), "\n")
   end
   return 0
end

local function explain(code, root, out, err)
   if not code then
      err:write("luasec: rules explain needs a code\n")
      return 2
   end
   local known = false
   for _, rule in ipairs(api.rule_catalogue()) do
      if rule.code == code then known = true end
   end
   if not known then
      err:write(("luasec: unknown code '%s': run 'luasec rules list' to see them\n"):format(code))
      return 2
   end
   local path = root .. "/docs/rules/" .. code .. ".md"
   local handle, open_error = io.open(path, "rb")
   if not handle then
      err:write("luasec: cannot read " .. path .. ": " .. tostring(open_error) .. "\n")
      return 2
   end
   out:write(handle:read("*a"))
   handle:close()
   return 0
end

--- Run `luasec rules <argv...>`. `argv` is what follows `rules`; `root` is the
-- installation directory. Returns the exit code.
function rules_cmd.run(argv, root, out, err)
   out, err = out or io.stdout, err or io.stderr
   local command = argv[1] or "list"
   if command == "list" then return list(out) end
   if command == "explain" then return explain(argv[2], root, out, err) end
   err:write(("luasec: unknown rules command '%s': expected list or explain\n"):format(command))
   return 2
end

return rules_cmd
