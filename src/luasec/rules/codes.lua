-- Warning code registry.
--
-- A code is the stable public identity of a finding. Every code declares its
-- severity, default confidence, CWE, message template and the extra fields its
-- findings carry. `docs/rules.md` must document every registered code; a spec
-- enforces that.
local codes = {}

local registry = {}

local function register(spec)
   assert(spec.code and spec.code:match("^%d%d%d$"), "code must be three digits: " .. tostring(spec.code))
   assert(not registry[spec.code], "duplicate warning code " .. spec.code)
   assert(spec.message, "code " .. spec.code .. " needs a message")
   assert(spec.severity, "code " .. spec.code .. " needs a severity")
   spec.fields = spec.fields or {}
   registry[spec.code] = spec
   return spec
end

local function sorted_codes(t)
   local keys = {}
   for k in pairs(t) do keys[#keys + 1] = k end
   table.sort(keys)
   return keys
end

codes.register = register
codes.get = function(code) return registry[code] end
codes.exists = function(code) return registry[code] ~= nil end
codes.all = function()
   local out = {}
   for _, code in ipairs(sorted_codes(registry)) do out[#out + 1] = registry[code] end
   return out
end
codes.count = function() local n = 0 for _ in pairs(registry) do n = n + 1 end return n end

--- Render a code's message template against a finding.
-- Placeholders are {field}; unknown placeholders are left alone so a typo is
-- visible in the report rather than silently swallowed.
function codes.render(spec, finding)
   local message = spec.message
   return (message:gsub("{(%w+)}", function(field)
      local value = finding[field]
      if value == nil then return "{" .. field .. "}" end
      return tostring(value)
   end))
end

-- ---------------------------------------------------------------- 7xx exec

register {code = "701", severity = "high", cwe = "CWE-78",
   message = "command execution with a non-constant argument ({name})"}

register {code = "702", severity = "high", cwe = "CWE-78",
   message = "pipe opened with a non-constant command ({name})"}

register {code = "703", severity = "high", cwe = "CWE-94",
   message = "dynamic code evaluation with a non-constant argument ({name})"}

register {code = "704", severity = "high", cwe = "CWE-94",
   message = "code or script loaded from a non-constant path ({name})"}

register {code = "705", severity = "high", cwe = "CWE-94",
   message = "module name computed at runtime ({name})"}

register {code = "706", severity = "high", cwe = "CWE-94",
   message = "native library loaded from a non-constant path ({name})"}

register {code = "707", severity = "high", cwe = "CWE-94",
   message = "LuaJIT FFI escape hatch used ({name})"}

-- Severity follows the sink it replaces, so it is registered as high; the
-- emitted finding copies the severity of the code it stands in for.
register {code = "708", severity = "high", cwe = "CWE-78",
   message = "execution sink in an exported function that nothing in this file feeds ({name})"}

register {code = "709", severity = "critical", cwe = "CWE-78", confidence = "high",
   message = "untrusted data reaches command execution ({name})",
   fields = {"sink", "source", "sources", "trace", "snippet", "sanitizer"}}

register {code = "710", severity = "critical", cwe = "CWE-94", confidence = "high",
   message = "untrusted data reaches dynamic code evaluation ({name})",
   fields = {"sink", "source", "sources", "trace", "snippet", "sanitizer"}}

register {code = "711", severity = "high", cwe = "CWE-78",
   message = "shell command written as a backtick literal"}

register {code = "712", severity = "high", cwe = "CWE-78", confidence = "high",
   message = "shell metacharacters from untrusted data are not quoted ({name})",
   fields = {"sink", "source", "sources", "trace", "snippet", "metachars"}}

-- ---------------------------------------------------------------- 7xx firmware

register {code = "721", severity = "high", cwe = "CWE-1236",
   message = "write to flash or firmware configuration with untrusted data ({name})",
   fields = {"sink", "source", "sources", "trace", "path"}}

register {code = "722", severity = "high", cwe = "CWE-78",
   message = "configuration value set from untrusted data, which a service may later execute ({name})",
   fields = {"sink", "source", "sources", "trace", "chain"}}

register {code = "723", severity = "medium", cwe = "CWE-538",
   message = "sensitive file read by path literal ({name})",
   fields = {"path"}}

register {code = "724", severity = "high", cwe = "CWE-78",
   message = "function containing an execution sink is exposed as an RPC handler ({name})",
   fields = {"sink", "exposed_as"}}

register {code = "725", severity = "high", cwe = "CWE-693",
   message = "sandbox or global environment manipulated ({name})"}

register {code = "726", severity = "medium", cwe = "CWE-732",
   message = "self-modifying or destructive operation ({name})"}

register {code = "727", severity = "medium", cwe = "CWE-400",
   message = "unbounded string growth can exhaust memory ({name})"}

register {code = "728", severity = "medium", cwe = "CWE-1333",
   message = "untrusted data used as a search pattern ({name})",
   fields = {"sink", "source", "sources", "trace"}}

-- ---------------------------------------------------------------- 7xx payload

register {code = "741", severity = "critical", cwe = "CWE-94",
   message = "obfuscated code loader ({name})"}

register {code = "742", severity = "high", cwe = "CWE-94",
   message = "precompiled code dump used to reconstitute a function ({name})"}

register {code = "743", severity = "critical", cwe = "CWE-94",
   message = "decoded data fed to an execution sink ({name})"}

register {code = "744", severity = "high", cwe = "CWE-94",
   message = "dynamic evaluation wrapped in error suppression ({name})"}

register {code = "745", severity = "medium", cwe = "CWE-693",
   message = "anti-analysis or watchdog behaviour ({name})"}

register {code = "746", severity = "critical", cwe = "CWE-506",
   message = "embedded machine-code blob ({name})"}

register {code = "747", severity = "high", cwe = "CWE-798",
   message = "hardcoded credential ({name})",
   fields = {"kind", "redacted"}}

register {code = "748", severity = "critical", cwe = "CWE-307",
   message = "scanner or credential brute-force loop ({name})"}

register {code = "749", severity = "high", cwe = "CWE-506",
   message = "persistence installed by the script ({name})"}

register {code = "750", severity = "critical", cwe = "CWE-1203",
   message = "matches a known exploit or malware signature: {name}",
   fields = {"signature", "pack_version"}}

-- ---------------------------------------------------------------- 8xx artifact

register {code = "801", severity = "medium", cwe = "CWE-0",
   message = "Lua bytecode file, source cannot be analyzed ({name})"}

register {code = "802", severity = "high", cwe = "CWE-94",
   message = "bytecode references an execution sink ({name})"}

register {code = "803", severity = "low", cwe = "CWE-0",
   message = "bytecode format does not match the assumed interpreter ({name})"}

register {code = "804", severity = "medium", cwe = "CWE-0",
   message = "highly obfuscated source ({name})"}

register {code = "805", severity = "low", cwe = "CWE-0",
   message = "file is not parseable Lua despite its name ({name})"}

-- ---------------------------------------------------------------- 0xx suppression

-- A `-- luasec:` directive the analyzer could not read: an action it does not
-- know, or a code pattern Lua cannot read as a pattern. It is in the 0xx range
-- with the other suppression problems, and it is a coverage gap rather than a
-- note: findings may have been kept or dropped other than the operator asked,
-- so a run with one of these does not pass.
--
-- This code was emitted for an unknown action from the start and never
-- registered, so a SARIF result could name a ruleId the tool did not declare,
-- and it sat on 021, which is luacheck's: a finding that means one thing in the
-- JSON and another in luacheck's own output. It is 012 now.
register {code = "012", severity = "low", cwe = "CWE-0",
   message = "a luasec suppression directive could not be read ({name})"}

-- ---------------------------------------------------------------- 9xx meta

register {code = "901", severity = "low", cwe = "CWE-0",
   message = "source could not be parsed; lexical scan only"}

register {code = "902", severity = "low", cwe = "CWE-0",
   message = "source uses a Lua construct the parser does not support ({name})"}

register {code = "903", severity = "low", cwe = "CWE-0",
   message = "API seen that is not available in the configured Lua standard ({name})"}

register {code = "904", severity = "medium", cwe = "CWE-0", confidence = "certain",
   message = "flow-sensitive analysis skipped for a large file ({name}); results are approximate",
   fields = {"node_count", "mode"}}

return codes
