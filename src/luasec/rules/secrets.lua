-- Rule module: secrets.
--
-- A detector is a function(ctx). It calls ctx:emit(code, node, extra) for each
-- finding. See src/luasec/rules/context.lua for what a context offers.
--
--   747  a secret written into the program: a literal bound to a name that
--        denotes one and holding a value that looks like one, or a PEM private
--        key block. A PEM *header* is the marker of a key, not a key. See the
--        747 notes in docs/rules.md for the two name tiers and the value rules.
--   748  a loop that opens a socket, reads what answers and sends a credential
--
-- The finding never carries the secret. It carries the name it was bound to,
-- how long the value is, and a masked form of it, because a report is read by
-- people who should not be handed the password by the tool that found it.
--
-- 747's registered severity is `high`, and it stays `high` wherever the value
-- really is a credential somebody chose. Two contexts lower one finding to
-- `low` and are the only two, because in both of them the value is a
-- credential-shaped literal that the finding has misread as an exposure:
--
--   * the file is part of a test suite (see rules/file_role.lua), and
--   * the value is the identity an anonymous login sends instead of a
--     password (see is_login_identity below).
--
-- Both lower the severity and neither drops the finding. A demotion is a
-- statement about exposure, not about detection, and the finding that only
-- cost a false `high` is not the one this rule may lose.
--
-- Code this module owns: 747, 748. See docs/rules.md.
local M = {}

local file_role = require "luasec.rules.file_role"

local detectors = {}

-- ------------------------------------------------------------ vocabulary

-- Words that make a name *unambiguous* about a secret. Matched against the
-- *words* a name is made of, so `db_password`, `wpaPsk`, `priv_key_pwd` and
-- `auth_token` all qualify while `monkey`, `author` and `compass` do not. Under
-- one of these the name is the evidence, and the value only has to look like
-- something an operator would not type into a text file.
local qualifying_words = {
   password = true, passwd = true, passphrase = true, pwd = true,
   secret = true, token = true, credential = true, credentials = true,
   apikey = true, psk = true, privkey = true, preshared = true,
}

-- Names whose parts are only evidence together. `api_key` is two ordinary
-- words, so it is matched on the name with its separators removed; the same
-- match catches `apiKey`, `APIKEY` and `x-api-key`.
local qualifying_compounds = { "apikey", "privatekey", "presharedkey" }

-- The weakest names in the list, and the ones this corpus got wrong: `key` is a
-- table index as likely as a credential, and `auth` is an 802.11
-- authentication mode as likely as a token. A value under one of these is
-- reported only when the value itself looks like a secret, and then at `low`
-- confidence, because the name is not evidence.
local weak_names = {
   key = true, keys = true, auth = true, pass = true, seed = true,
   licence = true, license = true,
}

-- Every word 748 treats as naming a credential a scanner sends or a login form
-- reads: the two tiers above plus the words that denote a *value used as a
-- credential* rather than a secret in its own right. 747 does not use this
-- union - it reads the two tiers, which say how much a name alone is worth.
local scanner_words = {
   password = true, passwd = true, passphrase = true, pwd = true, pass = true,
   key = true, keys = true, apikey = true, secret = true, token = true,
   credential = true, credentials = true, auth = true, psk = true,
   preshared = true, privkey = true, licence = true, license = true, seed = true,
   user = true, username = true, userid = true, user_id = true,
   login = true, account = true, cred = true,
}

-- Words that make a value a piece of vocabulary rather than a secret: a
-- protocol, a cipher, a mode, or the name of a certificate field. A value whose
-- every part is one of these is a program choosing an option, not a program
-- shipping a credential - `EAP-TLS` is `eap` and `tls`, `wpa-psk` is `wpa` and
-- `psk`, `ccmp` is itself. The parts are compared with the separators removed
-- and in lower case, so the spelling of the mode does not matter.
local vocabulary_words = {
   -- protocol and protocol family
   wpa = true, wpa2 = true, wpa3 = true, wep = true, wpaeap = true,
   eap = true, peap = true, ttls = true, tls = true, ssl = true,
   pap = true, chap = true, mschap = true, mschapv2 = true, eapmschapv2 = true,
   radius = true, ldap = true, ["local"] = true, none = true, psk = true,
   -- cipher and digest
   ccmp = true, tkip = true, aes = true, des = true, wpad = true, gcm = true,
   cbc = true, rsa = true, dsa = true, ecdsa = true, ed25519 = true,
   sha1 = true, sha256 = true, sha512 = true, md5 = true, hmac = true,
   -- mode and option
   ap = true, sta = true, adhoc = true, mesh = true, wds = true,
   client = true, server = true, auto = true, manual = true,
   disabled = true, optional = true, required = true, mandatory = true,
   open = true, shared = true, wepshared = true,
   -- the name of a certificate or key field
   country = true, state = true, locality = true, organization = true,
   organisation = true, commonname = true, email = true, unit = true,
}

-- Values that are protocol vocabulary, a mode, or a schema word: the name says
-- secret, the value says nothing was embedded.
local not_secrets = {
   ["true"] = true, ["false"] = true, ["nil"] = true, ["none"] = true,
   ["null"] = true, ["undefined"] = true,
   basic = true, bearer = true, digest = true, negotiate = true,
   md5 = true, sha1 = true, sha256 = true, sha512 = true, hmac = true,
   on = true, off = true, yes = true, ["no"] = true,
   get = true, post = true, put = true, delete = true, head = true,
   utf8 = true, ["utf-8"] = true, ascii = true, binary = true,
   text = true, json = true, xml = true, form = true, urlencoded = true,
   plain = true, pem = true, pkcs1 = true, pkcs8 = true, rsa = true,
   ecdsa = true, dsa = true, ed25519 = true, aes = true, des = true,
   tls = true, ssl = true, ssh = true, http = true, https = true,
   file = true, path = true, name = true, string = true, number = true,
   table = true, ["function"] = true, chunk = true, value = true, data = true,
   [""] = true, ["{}"] = true, ["0"] = true, ["1"] = true, ["-1"] = true,
}

-- Text that says a value is an example rather than a secret.
local placeholders = {
   "your", "yours", "changeme", "change_me", "change-me", "example",
   "placeholder", "todo", "fixme", "xxxx", "insert", "replace", "sample",
   "dummy", "redacted", "removed", "unset", "undefined", "here", "somevalue",
   "secret here", "filler", "lorem",
}

local MIN_SECRET_LENGTH = 4
local REVEALED_ENDS = 2
local MAX_MASK_STARS = 8

-- Under a *bare* `key` or `auth` the name is weak evidence, so the value has to
-- carry the evidence itself, and it needs twelve characters to do it. Every
-- protocol, mode and encryption token in the firmware corpora is shorter than
-- that - `EAP-TLS` is seven, `wpa` is three, `ccmp` is four - while every
-- credential that is really a credential in the same files is longer: a WPA PSK
-- is 8 to 63 characters by the standard, an API token or a key is longer
-- still, and the table indices and field names that share these names
-- (`max_memory_kb`, `timeout_ms`) are caught by the identifier test below
-- instead of by this floor.
local MIN_WEAK_VALUE_LENGTH = 12

-- The length under which an all-caps token is short enough to be a mode name.
-- The longest mode in the corpora is four characters (`WPA2`, `EAP`, `TTLS`).
local MAX_ENUM_LENGTH = 8

-- A base64 body is written 64 characters to the line, so a line over 64 is
-- prose. The floor is on the *longest* line rather than on every line, because
-- the last line of a body is short: it ends wherever the key ends. 40 is a
-- floor no real key is under - a 512-bit RSA private key is 316 base64
-- characters, an EC P-256 key 178 - and no line of English is over it.
local MAX_BASE64_LINE = 64
local MIN_BASE64_LINE = 40
local MIN_BASE64_BODY = 40

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

-- ------------------------------------------------------------ helpers

-- The words a name is made of: case and separators are not part of a name, so
-- `API_KEY`, `apiKey` and `api-key` are the same word list. The lower case has
-- to come first - a name spelled in capitals, which is how firmware spells
-- `API_TOKEN`, has no lower-case letters to match at all, and a splitter that
-- only looks for those sees no name.
local function words_of(name)
   local spaced = tostring(name):lower():gsub("(%l)(%u)", "%1 %2")
   local out = {}
   for word in spaced:gmatch("[%a%d]+") do
      out[#out + 1] = word:lower()
   end
   return out
end

-- How much a name is worth on its own: "strong" when the name says credential
-- without help, "weak" for the bare names where the value has to carry the
-- evidence, and nil when the name is not about a secret at all.
local function name_tier(name)
   local words = words_of(name)
   local glued = table.concat(words)

   for _, compound in ipairs(qualifying_compounds) do
      if glued:find(compound, 1, true) then return "strong" end
   end
   for _, word in ipairs(words) do
      if qualifying_words[word] then return "strong" end
   end
   for _, word in ipairs(words) do
      if weak_names[word] then return "weak" end
   end
   return nil
end

-- A name that denotes a credential a scanner sends or a login form reads. This
-- is 748's vocabulary, and it is a superset of 747's two tiers.
local function is_credential_name(name)
   for _, word in ipairs(words_of(name)) do
      if scanner_words[word] then return true end
   end
   return false
end

-- Which of the four kinds a finding is, from the name it was bound to.
local function kind_of(name)
   for _, word in ipairs(words_of(name)) do
      if word == "pem" or word == "pkcs1" or word == "pkcs8" then return "key" end
      if word == "key" or word == "apikey" or word == "psk" or word == "privkey"
            or word == "privatekey" or word == "preshared" or word == "seed"
            or word == "licence" or word == "license" then
         return "key"
      end
      if word == "token" or word == "auth" or word == "credential" or word == "credentials" then
         return "token"
      end
   end
   return "password"
end

-- A PEM private key block. Anchored at the start of the literal and matched
-- with plain character classes: no alternation, so a long run of letters
-- cannot make the matcher try every split.
local function pem_value(value)
   return value:find("^%-%-%-%-%-BEGIN ") == 1
      and value:find("PRIVATE KEY") ~= nil
end

-- A line that only says where a PEM block starts or ends.
local function pem_line(line)
   return line:match("^%-+[A-Z]+ [A-Z0-9 ]+%-+$") ~= nil
end

-- The marker of a PEM, as opposed to the key. `-----BEGIN RSA PRIVATE KEY-----`
-- is the first line of a PEM file, not a secret in it: a script that assembles
-- one at run time holds the marker and computes the base64 body, and the marker
-- is what a preamble table contains. A value is a marker when it opens a block
-- and every line of it is a BEGIN or an END line - a base64 line among them is
-- the key, not a marker.
local function pem_marker(value)
   if value:find("^%-+BEGIN ") ~= 1 then return false end
   local lines = 0
   for line in (value .. "\n"):gmatch("(.-)\n") do
      if line ~= "" then
         if not pem_line(line) then return false end
         lines = lines + 1
      end
   end
   return lines > 0
end

-- A private key block: a marker followed by the key material it introduces.
local function pem_key(value)
   return pem_value(value) and not pem_marker(value)
end

-- Suffixes that make a value a *reference* to a file rather than the file's
-- contents: a program that names its key is not the same as one that carries it.
local key_file_suffixes = {
   [".pem"] = true, [".key"] = true, [".der"] = true, [".crt"] = true, [".cer"] = true,
   [".p12"] = true, [".pfx"] = true, [".pub"] = true, [".asc"] = true, [".gpg"] = true,
   [".jks"] = true, [".ppk"] = true,
}

-- Does this value name a file rather than hold one?
local function looks_like_a_path(value)
   local lowered = value:lower()
   for suffix in pairs(key_file_suffixes) do
      if #lowered > #suffix and lowered:sub(-#suffix) == suffix then return true end
   end
   -- A path that begins at the root needs no dot to be one: `/etc/shadow` is a
   -- file. No secret begins with a separator, and no base64 body does either.
   if value:find("^[/~]") or value:find("^%.%.") then return true end
   -- A slash or backslash with a dotted file name after the last one reads as
   -- a path. A base64 secret holds a slash but no file name after it.
   local slash = lowered:find("[/\\]")
   if slash then
      local tail = lowered:sub(slash + 1):match("[^/\\]*$") or ""
      if tail:find("%.") then return true end
   end
   return false
end

-- A bare name holding a bare word: a limit name, a column name, a mode. Read
-- only under a weak name, where the name is not evidence and the value has to
-- be more than the shape of an identifier to carry it. A digit is that much:
-- `b41d8ef2a97c` is a key, `timeout_ms` is a field.
local function is_weak_value(value)
   if value:find("%d") then return false end
   return value:match("^[%a_][%w_]*$") ~= nil
end

-- A value that is vocabulary rather than a secret: every part of it, once the
-- separators and the case are gone, is a word from the table above. `EAP-TLS`,
-- `wpa-psk` and `ccmp` all decompose into nothing else.
local function is_vocabulary(value)
   local parts = 0
   for part in value:lower():gmatch("[%a%d]+") do
      if not vocabulary_words[part] then return false end
      parts = parts + 1
   end
   return parts > 0
end

-- An enum spelled in capitals: `WEP`, `WPA2`, `EAP-TLS`. A short all-caps token
-- or a hyphenated pair of them is how a mode is written, while a long unbroken
-- all-caps run is far more likely to be a real key - base64 without lowercase
-- happens - so that shape is left to the other tests.
local function is_all_caps_enum(value)
   if value:find("%l") then return false end
   if not value:find("%a") then return false end
   return #value <= MAX_ENUM_LENGTH or value:find("[^%w]") ~= nil
end

-- A number is a port, a timeout, a key length or a version, not a secret.
local function is_a_number(value)
   return value:match("^%d+$") ~= nil
end

-- The identity an anonymous login sends in place of a password.
--
-- The convention is that a client logging in as `anonymous` puts an address in
-- the PASS field, so that an administrator reading the server's log sees who
-- asked rather than seeing a blank. Every FTP client does it and every one
-- picks a different address, so the shape is the only thing that can be
-- recognised: a local part, an `@`, and either nothing after it or a domain
-- whose last label is letters.
--
-- NO LIST OF ALLOWED VALUES, deliberately. The strings are not anyone's to
-- enumerate - `anonymous`, `anonymous@`, `ftp@host`, `user@example.org` are all
-- in wide use and none of them is the one the next library will pick - and the
-- value that would have to be in such a list to catch `luasocket`'s
-- `anonymous@anonymous.org` is luasocket's own choice of domain, which is a
-- hard-coded string of one project in a table about a protocol. The shape
-- covers all of them at once and has nothing to go stale.
--
-- The bounds are what keep it from eating real passwords. A dotted domain with
-- a non-alphabetic last label is an IPv4 literal (`root@10.0.0.5`), an `@` with
-- anything after it that is not a domain is a password that happens to contain
-- one (`p@ssw0rd`), and the local part has to be three characters or more so a
-- two-letter value with a domain beside it is not read as an identity. Every
-- one of those bounds makes the rule demote LESS, which is the direction to err
-- in: what is left behind is a `high` finding, which is the finding this rule
-- would rather over-report than lose.
local function is_login_identity(value)
   if value:find("@", 1, true) == nil then return false end
   local local_part, domain = value:match("^([%w][%w%.%-_]*)@(.*)$")
   if not local_part or #local_part < 3 then return false end
   if domain == "" then return true end
   if domain:find("[^%w%.%-]") then return false end
   return domain:match("%.%a[%a]+$") ~= nil
end

-- A URL is a place a secret can be fetched from, not the secret.
local function is_a_url(value)
   return value:find("://", 1, true) ~= nil
end

-- The base64 body of a PEM: the lines a key block is written as, when the header
-- and the body are separate literals. A run of 40 base64 characters is a DER
-- blob, not prose, and a secret is the only thing in this language that is one.
local function is_base64_body(value)
   local characters, longest = 0, 0
   for line in (value .. "\n"):gmatch("(.-)\n") do
      if line ~= "" then
         if #line > MAX_BASE64_LINE then return false end
         if line:find("[^A-Za-z0-9+/=]") then return false end
         characters = characters + #line
         if #line > longest then longest = #line end
      end
   end
   return longest >= MIN_BASE64_LINE and characters >= MIN_BASE64_BODY
end

-- Is this literal a secret rather than a mode, a placeholder or a fragment?
local function looks_like_secret(value, floor)
   if type(value) ~= "string" then return false end
   floor = floor or MIN_SECRET_LENGTH
   local length = #value
   if length < floor then return false end

   -- Whitespace, and the bracket characters a placeholder is written with. The
   -- one whitespace-bearing shape that is a secret is the base64 body of a key.
   if value:find("[%s<>{}]") and not is_base64_body(value) then return false end
   if value:find("[%%$]") then return false end
   if is_a_url(value) then return false end
   if is_a_number(value) then return false end
   if is_all_caps_enum(value) then return false end
   if is_vocabulary(value) then return false end
   if looks_like_a_path(value) then return false end

   local lowered = value:lower()
   if not_secrets[lowered] then return false end
   for _, word in ipairs(placeholders) do
      if lowered:find(word, 1, true) then return false end
   end
   return true
end

-- The masked form of a value: the first and last two characters when there are
-- more than four of them, and stars for the rest. A short value is all stars,
-- because showing four of four would be showing all of it.
--
-- The middle is capped. A 400-character key would otherwise redact to a
-- 400-character run of nothing, and the `length` field already says how long
-- the value is: eight stars is enough to say there is a secret between these
-- two characters.
local function mask(value)
   local length = #value
   if length <= REVEALED_ENDS * 2 then return ("*"):rep(length) end
   local hidden = length - REVEALED_ENDS * 2
   if hidden > MAX_MASK_STARS then hidden = MAX_MASK_STARS end
   return value:sub(1, REVEALED_ENDS) .. ("*"):rep(hidden)
      .. value:sub(length - REVEALED_ENDS + 1)
end

-- The last dotted segment of a path, scanned by hand rather than matched with
-- a pattern: `([%w_]+)$` backtracks on a long identifier.
local function last_segment(path)
   local cut = 1
   for index = 1, #path do
      if path:sub(index, index) == "." then cut = index + 1 end
   end
   return path:sub(cut)
end

-- A stable label for a callee, matching the payloads module's vocabulary.
local function callee_label(ctx, call)
   local callee = call[1]
   if type(callee) ~= "table" then return nil end

   if call.tag == "Invoke" then
      -- A method call is `Invoke base, "name", args...`: the name is the
      -- call's own second slot, not a field of the base.
      local method = call[2]
      if type(method) == "table" and method.tag == "String" then
         local base = ctx:path_of(callee)
         return base and (base .. ":" .. method[1]) or method[1]
      end
      return nil
   end

   local path = ctx:path_of(callee)
   if path then return path end
   if callee.tag == "Id" and type(callee[1]) == "string" then return callee[1] end
   return nil
end

-- The Function node a callee was bound to, when the binding is visible.
local function defined_function(call)
   local callee = call[1]
   if type(callee) ~= "table" or callee.tag ~= "Id" or not callee.var then return nil end
   for _, value in ipairs(callee.var.values or {}) do
      if value.node and value.node.tag == "Function" then return value.node end
   end
   return nil
end

-- The parameter names of a function, in order, or an empty list.
local function parameters_of(fn)
   local out = {}
   if type(fn) ~= "table" or fn.tag ~= "Function" then return out end
   local args = fn[1]
   if type(args) ~= "table" then return out end
   for index, argument in ipairs(args) do
      if type(argument) == "table" and argument.tag == "Id" then
         out[index] = argument[1]
      end
   end
   return out
end

-- The string value of a node, or nil when it is not a string literal.
-- A secret split across concatenations at author time is still a literal in the
-- binary: `local key = "AAAA" .. "BBBB"` is one constant. Fold String and Concat
-- into the value the program will actually hold. The depth cap keeps a crafted
-- file proportional to its size.
local MAX_CONSTANT_CONCAT_DEPTH = 8

local function string_value(node, depth)
   if type(node) ~= "table" then return nil end
   if node.tag == "String" and type(node[1]) == "string" then
      return node[1]
   end
   depth = depth or 0
   -- luacheck spells concatenation as an `Op` node whose slot 1 is the operator
   -- name, so the operands are slots 2 and 3.
   if node.tag ~= "Op" or node[1] ~= "concat" or depth > MAX_CONSTANT_CONCAT_DEPTH then
      return nil
   end
   local left = string_value(node[2], depth + 1)
   local right = string_value(node[3], depth + 1)
   if not left or not right then return nil end
   return left .. right
end

-- A PEM block is reported by its header, which is not secret, plus the length.
-- Its middle is the key and its tail is key material in some variants, so no
-- characters of the body are shown at all.
local function pem_mask(value)
   local header = value:match("^%-%-%-%-%-BEGIN [A-Z0-9 ]*") or "-----BEGIN"
   return header .. "----- (" .. #value .. " bytes)"
end

-- ------------------------------------------------------------ 747

-- The severity 747 reports one literal at, or nil for the registered one.
--
-- `in_test` is a fact about the FILE, decided once by the caller, and `kind` is
-- what this finding's own evidence was: a credential-named binding, or a PEM
-- block that says what it is whatever name it is filed under. The two are
-- answered separately on purpose.
--
-- A PEM block is never demoted, and the reason is not that keys are common in
-- a test tree. The demotion below is about a finding whose evidence is a NAME -
-- and in a test suite a credential-named binding is the fixture, because
-- testing a credential field is what a fixture with a credential field is for.
-- A key block's evidence is the block itself, and a key is not a fixture shape:
-- it is material that authenticates something, people paste real development
-- keys into test directories, and the cost of reporting one is a line while the
-- cost of not reporting one is a credential that is in the repository.
--
-- The anonymous-login case is answered from the value alone, and only under a
-- strong PASSWORD name: a `token` that happens to hold an address is a token.
local function severity_for(value, kind, tier, in_test)
   if kind == "pem" then return nil end
   if in_test then return "low" end
   if tier == "strong" and kind == "password" and is_login_identity(value) then
      return "low"
   end
   return nil
end

-- Report one secret. `label` is the name the value was bound to; the value
-- itself never leaves this function. `tier` is how much the name was worth on
-- its own, and it is what the confidence says: a value under a name that means
-- credential is evidence in itself, a value under a bare `key` is only evidence
-- if it looks like a secret. `in_test` is whether the file is a test file.
local function report_secret(ctx, literal, label, kind, tier, in_test)
   local value = literal[1]
   ctx:emit("747", literal, {
      name = label,
      kind = kind,
      length = #value,
      severity = severity_for(value, kind, tier, in_test),
      confidence = tier == "weak" and "low" or "high",
      -- A PEM block is redacted by its header: the body is the key.
      redacted = kind == "pem" and pem_mask(value) or mask(value),
   })
end

-- The called function's name, however this parser spells the two call forms:
-- `Call` puts the name at [1] for a.b:c(...) and the receiver at [2] for a:b(...).
local function called_name(node)
   if type(node) ~= "table" then return "" end
   -- `a:b(...)` is an Invoke: slot 1 is the object, slot 2 the method name.
   if node.tag == "Invoke" then return string_value(node[2]) or "" end
   local callee = node[1]
   if type(callee) ~= "table" then return "" end
   -- `a.b(...)` is a Call whose callee is an Index: the name is the base, a dot
   -- and the field.
   if callee.tag == "Index" then
      local base = type(callee[1]) == "table" and callee[1][1] or nil
      local field = string_value(callee[2])
      if type(base) == "string" and field then return base .. "." .. field end
      return field or ""
   end
   if callee.tag == "Id" and type(callee[1]) == "string" then return callee[1] end
   return ""
end

-- The CBI fields that hold the value the user types. Everything else on a
-- control is metadata about it.
-- cfgvalue is in this list because it is the field the config value is READ
-- from in the real LuCI API, and datavalue is here because the LuCI Value type
-- documents it. One of the two is speculative on today's corpus; the other
-- appears 24 times.
local CBI_VALUE_FIELDS = {default = true, value = true, datavalue = true,
                          cfgvalue = true}

-- Config writers, by the name the call actually carries. This is the set the
-- OpenWrt profile declares, not a guess: a suffix match on `set` fires on
-- `m.set`, `db:set` and every other method that happens to be called set, and
-- `t:set("password", "...")` on an ordinary table is not a config write.
local CONFIG_WRITER_CALLS = {
   ["uci.set"] = true, ["uci.add"] = true, ["uci.sets"] = true,
}

local CONFIG_WRITE_METHODS = {set = true, add = true, setlist = true}

-- `uci.cursor()` and the cursors it returns, so `cursor:set(k, v)` is read as a
-- config write and `db:set(k, v)` is not.
--
-- Matched on the method name plus a cursor-ish factory, not on the receiver's
-- name: firmware aliases the module, so `muci.cursor()` and `uci.cursor()` are
-- the same object written two ways, and `luci.cursor` appears in more of the
-- corpus than the bare spelling. Matching the factory's last identifier is what
-- makes those two spellings agree.
-- Values assigned to table fields we can see, keyed "base.field" where base is
-- the name of the table. Built once per file, before any rule asks about a
-- cursor, because a call can appear before the assignment that defines it.
-- Per table field, what this file ever assigned to it: whether a handle, and
-- whether anything at all. See the pre-pass below.
local FIELD_VALUES = {}

local function field_key(node, field)
   if type(node) ~= "table" or node.tag ~= "Id" then return nil end
   local name = node[1]
   -- `field` is a String node's value, but this is also reached from paths
   -- where it is a node, and concatenating a table raises.
   if type(name) ~= "string" or type(field) ~= "string" then return nil end
   return name .. "." .. field
end

-- The summary for `base.field`, or nil when this file says nothing about it.
local function field_record(base, field)
   local key = field_key(base, field)
   if not key then return nil end
   return FIELD_VALUES[key]
end

-- The `uci` module, however it is reached: a local named for it, a global, or
-- a `require("uci")` the AST still shows us.
-- A receiver reached through a field or a global, so `self.uci:set(...)` and a
-- module-level `cursor` are followed as well as a local binding.
local MAX_CURSOR_HOPS = 6

-- How many reaching definitions of ONE local are followed.
--
-- The hop limit bounds the DEPTH of this walk, not its branching factor: every
-- Id reached is followed to each of its definitions, so a local reassigned N
-- times multiplies the work by N at each hop and the whole thing is
-- O(branches^depth). That was free while this ran once per USE of a field, and
-- it stopped being free when the answer moved into a pre-pass that runs once
-- per field ASSIGNMENT: a 369-line file with 60 reassignments chained through
-- five aliases did not finish in 300 s, and an ordinary 40,000-line module with
-- one heavily-reassigned local and 20,000 fields took 28 s where it had taken
-- 1.2 s. --max-nodes does not help, because `var.values` is filled by the parser
-- and exists even when resolve_locals was skipped.
--
-- Bounded here, newest definitions first, because the definition nearest the
-- use is the one that decides it.
local MAX_CURSOR_DEFS = 4

-- One answer per node, per file. The same local is reached from many fields and
-- the answer cannot differ between them.
local CURSOR_MEMO = {}

local function is_uci_module(node, depth)
   if type(node) ~= "table" or (depth or 0) > MAX_CURSOR_HOPS then return false end
   if node.tag == "Invoke" or node.tag == "Call" then
      if called_name(node) == "require" then
         local first = node.tag == "Invoke" and node[3] or node[2]
         -- `luci.model.uci` is the canonical LuCI path and `uci` the bare one;
         -- a module path is uci's when uci is a whole segment of it, or the
         -- whole of it. Substring matching would take `luci.sys` and `cusick`
         -- for a cursor.
         local module = string_value(first)
         if module == nil then return false end
         if module == "uci" or module == "muci" then return true end
         for segment in module:gmatch("[^%.]+") do
            if segment == "uci" or segment == "muci" then return true end
         end
         return false
      end
      return is_uci_module(node[1], (depth or 0) + 1)
   end
   if node.tag == "Id" then
      local name = type(node[1]) == "string" and node[1] or ""
      if string.find(name, "uci", 1, true) then return true end
      if node.var then
         for _, value in ipairs(node.var.values or {}) do
            if value.node and is_uci_module(value.node, (depth or 0) + 1) then
               return true
            end
         end
      end
   end
   return false
end

local function is_cursor(node, depth)
   if type(node) ~= "table" then return false end
   depth = depth or 0
   if depth > MAX_CURSOR_HOPS then return false end

   local memo = CURSOR_MEMO[node]
   if memo ~= nil then return memo end

   if node.tag == "Call" or node.tag == "Invoke" then
      -- Three ways firmware makes a cursor, and the spelling is not fixed:
      -- `uci.cursor()` and `muci.cursor()` name the module, a bare `cursor()`
      -- needs no name, and firmware wraps it in its own helper
      -- (`local c = mkcursor()`), which has no module to name either.
      --
      -- A named module that is NOT uci is rejected, so a library's own
      -- `sqlite.cursor()` is not a config write. Requiring "uci" in the name
      -- would have been tidier, but `mkcursor` has nothing in it.
      local name = called_name(node)
      if name == "" then return false end
      if string.find(name, "uci", 1, true) then return true end
      local callee = node[1]
      if type(callee) == "table" and callee.tag == "Index" then
         -- A module access, so the module is the base: `require("uci").cursor()`
         -- is the documented way to get one, and `sqlite.cursor()` is a
         -- different library's object that happens to share the field name.
         return is_uci_module(callee[1], depth + 1)
      end
      -- `mkcursor()` is a bare call: firmware's own helper, with no module
      -- behind it to rule out.
      return string.find(name, "cursor$") ~= nil
   end

   -- `self.uci` and `m.uci`: the field of a table that was built somewhere we
   -- can see. The field name carries the signal; the value is only followed so
   -- an alias of an alias still resolves.
   if node.tag == "Index" then
      -- Anchored at both ends on purpose. `^u?ci` alone matched cipher, cidr,
      -- citation, cities and circuit, which are ordinary identifiers in
      -- firmware code, and reported each one's :set as a config write. A field
      -- is a cursor when it is named like one, wholly.
      local field = string_value(node[2])
      if field == "uci" or field == "_uci" or field == "muci" or field == "cursor" then
         local record = field_record(node[1], field)
         -- Nothing assigned here that this file can see: `self.uci` is set by a
         -- constructor in another file, and the name is all there is.
         if record == nil then return true end
         -- Assigned here: a handle was, or nothing was. `t.uci = true` is not a
         -- config cursor, and a field assigned a handle and then a boolean on
         -- another path is a handle, because which way the program went decides.
         if record.handle then return true end
         if record.assigned then return false end
         return true
      end
      return is_cursor(node[1], depth + 1)
   end

   if node.tag == "Id" then
      -- A binding we can see is decided by what it is bound to. A local called
      -- `mycursor` holding a plain table is a plain table: reading its name
      -- instead of its definition reported every helper table whose author
      -- happened to end the name with cursor.
      if node.var then
         local values = node.var.values or {}
         for index = #values, math.max(1, #values - MAX_CURSOR_DEFS + 1), -1 do
            local value = values[index]
            if value and value.node and is_cursor(value.node, depth + 1) then
               CURSOR_MEMO[node] = true
               return true
            end
         end
         CURSOR_MEMO[node] = false
         return false
      end
      -- A global has no reaching definitions, so its name is all there is.
      local name = type(node[1]) == "string" and node[1] or ""
      return name == "uci" or name == "_uci" or name == "muci" or name == "cursor"
   end

   return false
end

local function config_writer(node)
   if node.tag == "Invoke" then
      return CONFIG_WRITE_METHODS[string_value(node[2]) or ""] == true
         and is_cursor(node[1])
   end
   -- `cur.set(...)` and `uci.set(...)` are the same write; a Call reaches a
   -- cursor the same way an Invoke does.
   if CONFIG_WRITER_CALLS[called_name(node)] then return true end
   local name = called_name(node)
   local tail = name:match("([%w_]+)$")
   if tail == nil or not CONFIG_WRITE_METHODS[tail] then return false end
   return is_cursor(node[1])
end

-- The CBI builders that take a field label as their first String argument.
local CBI_BUILDERS = {option = true, value = true, entry = true, sectionvalue = true,
                      ["list_value"] = true, ["section_value"] = true}

-- The label a CBI builder call carries, following one local binding so
-- `local o = s.option("Password", "d"); o.default = "x"` still resolves.
local function cbi_field_label(node)
   local name = called_name(node)
   local tail = name:match("([%w_]+)$") or name
   if not CBI_BUILDERS[tail] then return nil end
   -- `option("Password", "desc")` names the field first; `entry(section,
   -- "Key", "desc")` names it second, after the section it belongs to. Both
   -- openings are checked, and a name_tier hit decides which is which.
   local first = node.tag == "Invoke" and 3 or 2
   for position = first, first + 1 do
      local label = string_value(node[position])
      if label and name_tier(label) then return label end
   end
   return nil
end

-- How many reaching definitions of one local this follows. The same bound as
-- is_cursor and for the same reason: `#var.values` is one branch per syntactic
-- assignment, so an unbounded loop here is a fan-out, not a scan.
local MAX_LABEL_DEFS = 4

local function cbi_label_of_base(base, depth)
   if type(base) ~= "table" then return nil end
   depth = depth or 0
   if base.tag == "Call" or base.tag == "Invoke" then
      return cbi_field_label(base)
   end
   if base.tag ~= "Id" or not base.var or depth > 4 then return nil end
   local values = base.var.values or {}
   for index = #values, math.max(1, #values - MAX_LABEL_DEFS + 1), -1 do
      local value = values[index]
      if value and value.node then
         local label = cbi_label_of_base(value.node, depth + 1)
         if label then return label end
      end
   end
   return nil
end

detectors[#detectors + 1] = function(ctx)
   local reported = {}

   -- Whether this file is a test file, asked ONCE per file because it is a fact
   -- about the file and not about any one literal in it.
   --
   -- `file_path` is what `analyze_source` was given the source as, and it is nil
   -- when there was no file: `check_source` analyses a string. `file_role` reads
   -- a missing path as "not a test file", which is the answer that keeps the
   -- finding at its registered severity for a caller who never said otherwise.
   local in_test = file_role.is_test(ctx.chstate and ctx.chstate.file_path)

   -- First pass: what is assigned to each table field. A call can appear
   -- before the assignment that defines it, so this is collected before any
   -- rule asks whether something is a config cursor.
   for key in pairs(FIELD_VALUES) do FIELD_VALUES[key] = nil end
   for node in pairs(CURSOR_MEMO) do CURSOR_MEMO[node] = nil end
   ctx:each_node(function(node)
      if node.tag == "Set" or node.tag == "OpSet" or node.tag == "Local" then
         local targets, values = node[1], node[2]
         if type(targets) == "table" and type(values) == "table" then
            for index, target in ipairs(targets) do
               if type(target) == "table" and target.tag == "Index" then
                  local key = field_key(target[1], string_value(target[2]))
                  if key then
                     -- `local t = {} ; t.a, t.b = 1` has two targets and one
                     -- value, so values[2] is nil. `(value == nil) and false or
                     -- value.tag` evaluates the right operand anyway, indexed nil,
                     -- and raised inside the rule: every secrets finding in the
                     -- file was replaced by "a rule failed to run". It fires on
                     -- four files in the corpus, on an idiom that is everywhere.
                     local value = values[index]
                     if type(value) == "table" then
                        -- Summarised to a fact, not kept as a list. The list was
                        -- quadratic: the answer is asked once per use of the field
                        -- and the uses are once per line, so 32,000 assignments
                        -- with 32,000 uses took 109 s where the earlier build took
                        -- 5 s.
                        --
                        -- Capping the list fixed the time and cost a finding, which
                        -- is the one direction this tool may not fail in: a cursor
                        -- assigned as the ninth value to a field was invisible,
                        -- and a hardcoded credential written through it went
                        -- unreported. A cap is positional. This boolean answers
                        -- the actual question - was a handle ever assigned here -
                        -- in O(1) per assignment and O(1) per use, and cannot
                        -- lose the ninth cursor.
                        --
                        -- Asked with `is_cursor` and not with a test for whether
                        -- the value is a call. A test for the tag answers a
                        -- DIFFERENT question, and it was wrong in both
                        -- directions: six shapes that store a cursor rather than
                        -- call one went dark at every position
                        -- (`local c = uci.cursor(); M.uci = c`, an alias chain,
                        -- `self.cursor`, an uncalled `uci.cursor`, a global
                        -- `cursor`, `t2.uci`) while `f()`, `t.setup()`,
                        -- `db:query()` and `setmetatable({}, {})` all became
                        -- config writes, including another library's
                        -- `store.cursor`. A hardcoded root password written
                        -- through a stored cursor went unreported, which is the
                        -- one direction this may not fail in.
                        --
                        -- Nothing caught it: the corpus's 747 count is 0 whatever
                        -- this rule does, and no fixture assigned a non-call
                        -- cursor to a field. 568 specs and a 146-finding corpus
                        -- measurement all agreed with the broken rule.
                        --
                        -- The walk behind `is_cursor` is bounded in depth AND in
                        -- fan-out, because a pre-pass call costs one branch per
                        -- reaching definition per hop: unbounded, a 369-line file
                        -- did not finish in 300 s and an ordinary 40,000-line
                        -- module took 28 s where it had taken 1.2 s.
                        local record = FIELD_VALUES[key] or {handle = false, assigned = false}
                        record.assigned = true
                        if is_cursor(value, 0) then record.handle = true end
                        FIELD_VALUES[key] = record
                     end
                  end
               end
            end
         end
      end
   end)

   -- One literal, one finding: a value bound twice, or bound and compared, is
   -- the same secret and is reported where it was embedded.
   local function consider(literal, label)
      if not literal or reported[literal] then return end
      local value = string_value(literal)
      if not value then return end

      -- The marker a script writes around a PEM it assembles at run time is
      -- not a secret: the key material is the base64 body, and a marker has
      -- none. Read before the name, because `key` is the name a preamble
      -- table gives a header line.
      if pem_marker(value) then return end

      -- A private key block is a secret whatever it is called, and is read
      -- before the name is: the block says what it is.
      if pem_key(value) then
         reported[literal] = true
         report_secret(ctx, literal, label, "pem", nil, in_test)
         return
      end
      local tier = name_tier(label)
      if not tier then return end
      local floor = tier == "weak" and MIN_WEAK_VALUE_LENGTH or MIN_SECRET_LENGTH
      if not looks_like_secret(value, floor) then return end
      if tier == "weak" and is_weak_value(value) then return end
      reported[literal] = true
      report_secret(ctx, literal, label, kind_of(label), tier, in_test)
   end

   ctx:each_node(function(node)
      local tag = node.tag

      if tag == "Local" or tag == "Localrec" or tag == "Set" or tag == "OpSet" then
         -- A write is `tag, {targets...}, {values...}`; the parser keeps no
         -- names on the parts, so the slots are read by position.
         local targets, values = node[1], node[2]
         if type(targets) ~= "table" or type(values) ~= "table" then return end
         for index, target in ipairs(targets) do
            local label = target[1]
            if target.tag == "Id" and type(label) == "string" and name_tier(label) then
               consider(values[index], label)
            elseif target.tag == "Index" then
               local key = string_value(target[2])
               if key and name_tier(key) then
                  local base = target[1]
                  consider(values[index],
                     base.tag == "Id" and type(base[1]) == "string"
                        and (base[1] .. "." .. key) or key)
               else
                  -- The CBI form:
                  -- `s.option("Password", "desc").default = "<literal>"`. The
                  -- builder call names the field and this assignment carries
                  -- the value.
                  --
                  -- Only the fields that carry a value count. A CBI control has
                  -- one of those and about a dozen that describe it, and the
                  -- descriptors are all short strings: reporting
                  -- `public_key.datatype = "and(base64,rangelength(44,44))"`
                  -- as a hardcoded credential is the same class of mistake as
                  -- the 17 false positives this rule once produced.
                  local label = CBI_VALUE_FIELDS[key] and cbi_label_of_base(target[1])
                  if label then consider(values[index], label) end
               end
            end
         end

      elseif tag == "Table" then
         for _, pair_node in ipairs(node) do
            if pair_node.tag == "Pair" and pair_node[1] and pair_node[1].tag == "String" then
               local key = pair_node[1][1]
               if name_tier(key) then consider(pair_node[2], key) end
            end
         end

      elseif tag == "Call" or tag == "Invoke" then
         -- A literal passed to a parameter the program itself named as a secret
         -- is just as embedded as one assigned to a variable.
         local fn = defined_function(node)
         if fn then
            local parameters = parameters_of(fn)
            local first = node.tag == "Invoke" and 3 or 2
            for position = first, #node do
               local parameter = parameters[position - first + 1]
               if type(parameter) == "string" and name_tier(parameter) then
                  consider(node[position], parameter)
               end
            end
         end

         -- A CBI option can also be built with its value inline:
         -- `s:option("Password", "desc", {cfgvalue = "..."})`. The field name
         -- is not a credential name, so the Table branch above ignores it, and
         -- the label is the one this call carries.
         local inline_label = cbi_field_label(node)
         if inline_label then
            local inline_first = node.tag == "Invoke" and 3 or 2
            for position = inline_first, #node do
               local argument = node[position]
               if type(argument) == "table" and argument.tag == "Table" then
                  for _, pair_node in ipairs(argument) do
                     if pair_node.tag == "Pair" and type(pair_node[1]) == "table"
                        and pair_node[1].tag == "String"
                        and CBI_VALUE_FIELDS[pair_node[1][1]] then
                        consider(pair_node[2], inline_label)
                     end
                  end
               end
            end
         end

         -- uci.set("wireless", "default", "key", "<literal>") writes a secret
         -- into the flash config without ever naming a variable. The key is a
         -- String argument, the value is the argument after it, and the call has
         -- to be a config writer or this would fire on any two adjacent strings.
         if config_writer(node) then
            local first_argument = node.tag == "Invoke" and 3 or 2
            for position = first_argument, #node do
               local key = string_value(node[position])
               if key and name_tier(key) then
                  consider(node[position + 1], key)
               end
            end
         end

      end
   end)

   -- A key block is a secret whatever name it is filed under, so the literals
   -- are read on their own as well. A lone header line is not a block.
   ctx:each_string(function(literal, value)
      if type(value) == "string" and pem_key(value) then
         consider(literal, "PEM private key")
      end
   end)
end

-- ------------------------------------------------------------ 748

-- Work caps, so a file crafted to be expensive stays proportional to its size.
local MAX_BODY_NODES = 600
local MAX_CREDENTIAL_SEARCH = 64
local MAX_TREE_DEPTH = 200

-- Calls that open or reach a network connection, however the library spells it.
local connects = {
   connect = true, tcp = true, udp = true, bind = true, accept = true,
   ["socket.tcp"] = true, ["socket.udp"] = true, ["socket.bind"] = true,
   ["nixio.socket"] = true, ["posix.socket"] = true, ["socket.connect"] = true,
   ["net.connect"] = true, ["socket.create"] = true,
}

-- Calls that read from one, which is where a banner comes from.
local reads = {
   receive = true, recv = true, recvfrom = true, read = true,
}

-- Calls that put bytes on a connection, which is where a credential goes.
local sends = {
   send = true, sendto = true, write = true, writeto = true,
   ["socket.send"] = true, ["socket.write"] = true,
}

-- Forward declarations: the one-pass walk, the helper-shape test and the
-- evidence they share refer to each other.
local helper_shape, walk_children, walk_statements

-- Visit every tagged node in a list of nodes. A block is a plain list, so the
-- list case is the common one; a node is just a list of length one here.
walk_children = function(node, visit, depth)
   if type(node) ~= "table" then return end
   for index = 1, #node do
      local child = node[index]
      if type(child) == "table" then
         if child.tag then
            visit(child, depth)
         else
            for _, sub in ipairs(child) do
               if type(sub) == "table" and sub.tag then visit(sub, depth) end
            end
         end
      end
   end
end

-- Visit the statements of a function body, which is a plain list.
walk_statements = function(body, visit, depth)
   if type(body) ~= "table" then return end
   for index = 1, #body do
      local statement = body[index]
      if type(statement) == "table" and statement.tag then visit(statement, depth) end
   end
end

local loops = {While = true, Repeat = true, Fornum = true, Forin = true}

local function is_loop(tag)
   return loops[tag] == true
end

-- The body of a loop, in the slot the parser gave each kind: a numeric for
-- grows a step slot ahead of the body, and a repeat puts the body first.
local function loop_body(loop)
   local tag = loop.tag
   if tag == "While" then return loop[2] end
   if tag == "Repeat" then return loop[1] end
   if tag == "Forin" then return loop[3] end
   return loop[5] or loop[4]
end

-- The method of a call, without the base: `client:send` is `send`.
local function method_of(call)
   if call.tag ~= "Invoke" then return nil end
   local method = call[2]
   if type(method) == "table" and method.tag == "String" then return method[1] end
   return nil
end

-- Does this expression name a credential? A scanner builds the line it sends
-- out of the names it was given, so the names are the evidence.
local function mentions_credential(node, budget)
   if budget <= 0 or type(node) ~= "table" then return false end
   budget = budget - 1
   local tag = node.tag

   if tag == "Function" then return false end
   if tag == "Id" then
      return type(node[1]) == "string" and is_credential_name(node[1])
   elseif tag == "Index" then
      local key = node[2]
      if type(key) == "table" and key.tag == "String" then
         return is_credential_name(key[1])
      end
   elseif tag == "Paren" then
      return mentions_credential(node[1], budget)
   end

   for index = 1, #node do
      local child = node[index]
      if type(child) == "table" then
         local kids = child.tag and {child} or child
         for _, sub in ipairs(kids) do
            if type(sub) == "table" and mentions_credential(sub, budget) then return true end
         end
      end
   end
   return false
end

-- A table of credential pairs: `{{user = "root", pass = "admin"}}`, or the
-- `{"root:admin"}` form a scanner carries when it packs one string per line.
local function is_credential_table(node)
   if type(node) ~= "table" or node.tag ~= "Table" then return false end
   for index = 1, #node do
      local entry = node[index]
      if type(entry) ~= "table" then return false end
      if entry.tag == "Table" then
         local named = {}
         for _, pair_node in ipairs(entry) do
            if pair_node.tag == "Pair" and type(pair_node[1]) == "table"
                  and pair_node[1].tag == "String" and is_credential_name(pair_node[1][1]) then
               named[pair_node[1][1]] = true
            end
         end
         local count = 0
         for _ in pairs(named) do count = count + 1 end
         if count >= 2 then return true end
      elseif entry.tag == "String" and entry[1]:find(":", 1, true) then
         return true
      end
   end
   return false
end

-- The Table node a value was bound to, following one local or one field.
local function resolve_table(node, depth)
   depth = depth or 0
   if depth > 4 or type(node) ~= "table" then return nil end
   if node.tag == "Table" then return node end
   if node.tag == "Paren" then return resolve_table(node[1], depth + 1) end
   if node.tag == "Call" and #node >= 2 then
      -- `ipairs(t)` / `pairs(t)`: the table is the argument.
      return resolve_table(node[2], depth + 1)
   end
   if node.tag == "Id" and node.var then
      for _, value in ipairs(node.var.values or {}) do
         if value.node and value.node.tag == "Table" then return value.node end
      end
   end
   return nil
end

-- Is this loop iterating a table of credential pairs?
local function iterates_credentials(loop)
   if loop.tag ~= "Forin" then return false end
   local expressions = loop[2]
   if type(expressions) ~= "table" then return false end
   for index = 1, #expressions do
      if is_credential_table(resolve_table(expressions[index])) then return true end
   end
   return false
end

-- What a body of code does on a connection, gathered in one pass: where it
-- connected, what it read back, and where it sent something.
local function new_evidence(node)
   return {node = node, connect = nil, read = nil, send = nil,
      credential = false, pairs = false}
end

-- Fold one call into the evidence of the loop it belongs to.
local function observe(ctx, entry, call, cache)
   local label = callee_label(ctx, call)
   if not label then return end
   local method = method_of(call)
   local short = method or last_segment(label)

   if connects[short] then
      entry.connect = entry.connect or label
      return
   end
   if reads[short] then
      entry.read = entry.read or label
      return
   end
   if sends[short] then
      if not entry.send then
         entry.send = label
         entry.credential = false
         for index = (method and 3 or 2), #call do
            if mentions_credential(call[index], MAX_CREDENTIAL_SEARCH) then
               entry.credential = true
               break
            end
         end
      end
      return
   end

   -- A helper this file defines: if it connects and sends, the loop that calls
   -- it is doing the scanning, one call out. One level only, and cached, so a
   -- loop that calls a helper that calls a helper stops here.
   local fn = defined_function(call)
   if not fn then return end
   local shape = helper_shape(ctx, fn, cache)
   if not shape then return end
   entry.connect = entry.connect or shape.connect
   entry.read = entry.read or shape.read
   if not entry.send and shape.send then
      entry.send = shape.send
      entry.credential = shape.credential
   end
end

-- The connection work a function defined in this file does, or nil when it
-- does none. The answer is cached: one body, one walk.
helper_shape = function(ctx, fn, cache)
   if cache[fn] ~= nil then return cache[fn] or nil end
   cache[fn] = false
   local entry = new_evidence(fn)
   local scanned = 0

   local function visit(node, depth)
      if scanned >= MAX_BODY_NODES or depth > MAX_TREE_DEPTH then return end
      scanned = scanned + 1
      if node.tag == "Call" or node.tag == "Invoke" then
         observe(ctx, entry, node, cache)
         return
      end
      -- A nested function is its own work, not this one's.
      if node.tag == "Function" then return end
      walk_children(node, visit, depth + 1)
   end

   walk_statements(fn[2], visit, 0)
   if not entry.send then return nil end
   cache[fn] = entry
   return entry
end

-- 748: a loop that opens a connection, reads what answers and sends a
-- credential.
--
-- This walks the tree once, keeping the loops it is inside on a stack, so every
-- call is looked at once and every loop's evidence is its own: `each_node`
-- hands out nodes with no parents, and asking each loop to re-walk its body
-- would look at the same call once per enclosing loop.
detectors[#detectors + 1] = function(ctx)
   local cache = {}
   local stack = {}

   local function current()
      return stack[#stack]
   end

   local function visit(node, depth)
      if depth > MAX_TREE_DEPTH or type(node) ~= "table" then return end
      local tag = node.tag
      if not tag then return end

      if is_loop(tag) then
         local entry = new_evidence(node)
         entry.pairs = iterates_credentials(node)
         stack[#stack + 1] = entry
         walk_children(loop_body(node), visit, depth + 1)
         stack[#stack] = nil
         if entry.connect and entry.send and (entry.credential or entry.pairs) then
            ctx:emit("748", node, {
               name = entry.send,
               sink = entry.send,
               connect = entry.connect,
               read = entry.read,
            })
         end
         return
      end

      if tag == "Call" or tag == "Invoke" then
         local entry = current()
         if entry then observe(ctx, entry, node, cache) end
      end

      walk_children(node, visit, depth + 1)
   end

   walk_children(ctx.chstate.ast, visit, 0)
end

return M
