-- Rule module: secrets.
--
-- A detector is a function(ctx). It calls ctx:emit(code, node, extra) for each
-- finding. See src/luasec/rules/context.lua for what a context offers.
--
--   747  a secret written into the program: a literal bound to a name that
--        denotes one, or a PEM private key block
--   748  a loop that opens a socket, reads what answers and sends a credential
--
-- The finding never carries the secret. It carries the name it was bound to,
-- how long the value is, and a masked form of it, because a report is read by
-- people who should not be handed the password by the tool that found it.
--
-- Code this module owns: 747, 748. See docs/rules.md.
local M = {}

local detectors = {}

-- ------------------------------------------------------------ vocabulary

-- Words that denote a secret. Matched against the *words* a name is made of, so
-- `db_password`, `API_KEY`, `wpaPsk` and `pre_shared_key` all hit while
-- `monkey`, `author` and `compass` do not.
local secret_words = {
   password = true, passwd = true, passphrase = true, pwd = true, pass = true,
   key = true, apikey = true, secret = true, token = true,
   credential = true, credentials = true, auth = true,
   psk = true, preshared = true, privkey = true, privatekey = true,
   licence = true, license = true, seed = true,
}

-- Words that denote a *value used as a credential* rather than a secret in its
-- own right. A scanner sends these; a login form reads them.
local credential_words = {
   user = true, username = true, userid = true, user_id = true,
   login = true, account = true, cred = true,
}

-- The weakest names in the list. `key` on its own is as likely to be a table
-- index - a table of limits keyed by the name of the limit - as it is a
-- secret, so a bare word under one of these names is not reported. A digit, a
-- symbol, or a name with a qualifier (`api_key`, `M.key`) is.
local weak_names = {
   key = true, keys = true, seed = true,
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

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

-- ------------------------------------------------------------ helpers

-- The words a name is made of: case and separators are not part of a name, so
-- `API_KEY`, `apiKey` and `api-key` are the same word list.
local function words_of(name)
   local spaced = tostring(name):gsub("(%l)(%u)", "%1 %2")
   local out = {}
   for word in spaced:gmatch("[%l%d]+") do
      out[#out + 1] = word:lower()
   end
   return out
end

local function is_secret_name(name)
   for _, word in ipairs(words_of(name)) do
      if secret_words[word] then return true end
   end
   return false
end

local function is_credential_name(name)
   for _, word in ipairs(words_of(name)) do
      if secret_words[word] or credential_words[word] then return true end
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
   -- A slash or backslash with a dotted file name after the last one reads as
   -- a path. A base64 secret holds a slash but no file name after it.
   local slash = lowered:find("[/\\]")
   if slash then
      local tail = lowered:sub(slash + 1):match("[^/\\]*$") or ""
      if tail:find("%.") then return true end
   end
   return false
end

-- A bare `key` holding a bare word: a limit name, a column name, a mode. The
-- name is the only evidence, and the value says the same thing the name did.
local function is_weak_value(label, value)
   if not weak_names[label] then return false end
   if value:find("%d") then return false end
   return value:match("^[%a_][%w_]*$") ~= nil
end

-- Is this literal a secret rather than a mode, a placeholder or a fragment?
local function looks_like_secret(value)
   if type(value) ~= "string" then return false end
   local length = #value
   if length < MIN_SECRET_LENGTH then return false end

   -- Whitespace, and the bracket characters a placeholder is written with.
   if value:find("[%s<>{}]") then return false end
   if value:find("[%%$]") then return false end
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
local function mask(value)
   local length = #value
   if length <= REVEALED_ENDS * 2 then return ("*"):rep(length) end
   return value:sub(1, REVEALED_ENDS) .. ("*"):rep(length - REVEALED_ENDS * 2)
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
local function string_value(node)
   if type(node) == "table" and node.tag == "String" and type(node[1]) == "string" then
      return node[1]
   end
   return nil
end

-- A PEM block is reported by its header, which is not secret, plus the length.
-- Its middle is the key and its tail is key material in some variants, so no
-- characters of the body are shown at all.
local function pem_mask(value)
   local header = value:match("^%-%-%-%-%-BEGIN [A-Z0-9 ]*") or "-----BEGIN"
   return header .. "----- (" .. #value .. " bytes)"
end

-- ------------------------------------------------------------ 747

-- Report one secret. `label` is the name the value was bound to; the value
-- itself never leaves this function.
local function report_secret(ctx, literal, label, kind)
   local value = literal[1]
   ctx:emit("747", literal, {
      name = label,
      kind = kind,
      length = #value,
      -- A PEM block is redacted by its header: the body is the key.
      redacted = kind == "pem" and pem_mask(value) or mask(value),
   })
end

detectors[#detectors + 1] = function(ctx)
   local reported = {}

   -- One literal, one finding: a value bound twice, or bound and compared, is
   -- the same secret and is reported where it was embedded.
   local function consider(literal, label)
      if not literal or reported[literal] then return end
      local value = string_value(literal)
      if not value then return end

      -- A private key block is a secret whatever it is called, and is read
      -- before the name is: the block says what it is.
      if pem_value(value) then
         reported[literal] = true
         report_secret(ctx, literal, label, "pem")
         return
      end
      if not looks_like_secret(value) then return end
      if is_weak_value(label, value) then return end
      reported[literal] = true
      report_secret(ctx, literal, label, kind_of(label))
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
            if target.tag == "Id" and type(label) == "string" and is_secret_name(label) then
               consider(values[index], label)
            elseif target.tag == "Index" and target[2] and target[2].tag == "String" then
               local key = target[2][1]
               if is_secret_name(key) then
                  local base = target[1]
                  consider(values[index],
                     base.tag == "Id" and type(base[1]) == "string"
                        and (base[1] .. "." .. key) or key)
               end
            end
         end

      elseif tag == "Table" then
         for _, pair_node in ipairs(node) do
            if pair_node.tag == "Pair" and pair_node[1] and pair_node[1].tag == "String" then
               local key = pair_node[1][1]
               if is_secret_name(key) then consider(pair_node[2], key) end
            end
         end

      elseif tag == "Call" or tag == "Invoke" then
         -- A literal passed to a parameter the program itself named as a secret
         -- is just as embedded as one assigned to a variable.
         local fn = defined_function(node)
         if not fn then return end
         local parameters = parameters_of(fn)
         local first = node.tag == "Invoke" and 3 or 2
         for position = first, #node do
            local parameter = parameters[position - first + 1]
            if type(parameter) == "string" and is_secret_name(parameter) then
               consider(node[position], parameter)
            end
         end
      end
   end)

   -- A key block is a secret whatever name it is filed under, so the literals
   -- are read on their own as well.
   ctx:each_string(function(literal, value)
      if type(value) == "string" and pem_value(value) then
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
