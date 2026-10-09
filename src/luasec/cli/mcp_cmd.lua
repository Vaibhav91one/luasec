-- `luasec mcp`: an MCP server on stdio (newline-delimited JSON-RPC 2.0) with one
-- tool, `scan`. The tool runs the CLI itself, as a child process with --json, and
-- hands back its standard output untouched, so the envelope is byte-identical to
-- `luasec --json <path>` for the same arguments and there is no second scan path
-- to drift from the first. Over MCP the CLI's `--help`, `--version`, `--stdin`,
-- `--validate`, `--format`, `-o`, the interactive and progress flags and the
-- config/selection flags other than the ones below are not offered.
local json = require "luasec.report.json"
local findings = require "luasec.report.findings"
local version = require "luasec.version"

local mcp = {}

-- tool argument -> CLI flag. Values are passed as `--flag=value`, so a value that
-- starts with a dash can never be read as another option.
local STRING_FLAGS = {
   baseline = "--baseline", fail_on = "--fail-on", sarif = "--sarif", std = "--std",
   min_confidence = "--min-confidence", severity_threshold = "--severity-threshold",
}

local SCHEMA = {
   type = "object",
   properties = {
      path = {description = "File or directory to scan (or a list of them)",
         anyOf = {{type = "string"}, {type = "array", items = {type = "string"}}}},
      baseline = {type = "string", description = "A previous --json envelope; only new findings fail the run"},
      fail_on = {type = "string", enum = {"critical", "high", "medium", "low", "info"},
         description = "Severity at or above which the run exits 1 (default low)"},
      sarif = {type = "string", description = "Also write SARIF 2.1.0 to this file"},
      std = {type = "string", description = "Platform API sets, e.g. +openwrt+luci"},
      min_confidence = {type = "string", enum = {"certain", "high", "medium", "low"}},
      severity_threshold = {type = "string", enum = {"critical", "high", "medium", "low"}},
      whole_program = {type = "boolean", description = "Resolve calls across files"},
   },
   required = {"path"},
}

local function quote(text)
   return "'" .. (tostring(text):gsub("'", "'\\''")) .. "'"
end

-- The interpreter running this process, and the script it was started with, so
-- the child is the same Lua on the same sources.
local function interpreter()
   local lowest = 0
   while arg[lowest - 1] do lowest = lowest - 1 end
   return os.getenv("LUASEC_LUA") or arg[lowest]
end

-- Run the scan. Returns the CLI's stdout and true, or an explanation and false.
local function scan(args)
   local paths = type(args.path) == "string" and {args.path} or args.path
   if type(paths) ~= "table" or #paths == 0 then return "path is required", false end
   local words = {quote(interpreter()), "-e", quote("package.path=" .. ("%q"):format(package.path)),
      quote(arg[0]), "--json", "--no-progress", "--no-interactive"}
   for name, flag in pairs(STRING_FLAGS) do
      if args[name] ~= nil then
         if type(args[name]) ~= "string" then return name .. " must be a string", false end
         words[#words + 1] = quote(flag .. "=" .. args[name])
      end
   end
   if args.whole_program == true then words[#words + 1] = "--whole-program" end
   words[#words + 1] = "--"
   for _, path in ipairs(paths) do
      if type(path) ~= "string" then return "path must be a string or a list of strings", false end
      words[#words + 1] = quote(path)
   end

   local errors = os.tmpname()
   -- luasec: ignore 709  every word is shell-quoted, and client values only follow `--flag=` or `--`
   local handle = io.popen(table.concat(words, " ") .. " 2>" .. quote(errors), "r")
   local out = handle:read("a")
   local _, _, code = handle:close()
   local stderr = io.open(errors, "rb")
   local message = stderr and stderr:read("a") or ""
   if stderr then stderr:close() end
   os.remove(errors)
   -- 0 clean, 1 findings, 3 new findings: all three print an envelope. 2 is a
   -- usage or input error and prints a message on stderr instead.
   if code == 0 or code == 1 or code == 3 then return out, true end
   return (message ~= "" and message or out), false
end

local function handle_request(request)
   local method, params = request.method, request.params or {}
   if method == "initialize" then
      return {protocolVersion = params.protocolVersion or "2024-11-05",
         capabilities = {tools = {listChanged = false}},
         serverInfo = {name = "luasec", version = version.luasec}}
   elseif method == "ping" then
      return json.object
   elseif method == "tools/list" then
      return {tools = {{name = "scan", inputSchema = SCHEMA,
         description = "Scan Lua code for security findings. Returns the doctor/1 JSON envelope, "
            .. "the same text as `luasec --json <path>`."}}}
   elseif method == "tools/call" then
      if params.name ~= "scan" then return nil, -32602, "unknown tool " .. tostring(params.name) end
      local text, ok = scan(type(params.arguments) == "table" and params.arguments or {})
      return {content = {{type = "text", text = text}}, isError = not ok}
   end
   return nil, -32601, "method not found: " .. tostring(method)
end

local function send(message)
   message.jsonrpc = "2.0"
   io.stdout:write(json.encode(message, false), "\n")
   io.stdout:flush()
end

function mcp.run()
   for line in io.stdin:lines() do
      if line:find("%S") then
         local ok, request = pcall(findings.decode, line)
         if not ok or type(request) ~= "table" or type(request.method) ~= "string" then
            send({id = json.null, error = {code = ok and -32600 or -32700, message = "invalid request"}})
         elseif request.id ~= nil then
            local result, code, message = handle_request(request)
            if result then
               send({id = request.id, result = result})
            else
               send({id = request.id, error = {code = code, message = message}})
            end
         end
         -- A notification (no id), such as notifications/initialized, gets no reply.
      end
   end
   return 0
end

return mcp
