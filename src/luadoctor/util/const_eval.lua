-- Constant folding for AST expressions.
--
-- A taint-only analyzer drowns in false positives if `os.execute("ping " .. "8.8.8.8")`
-- counts as dangerous. This answers the only question the sink check needs: is
-- this expression's value fixed at parse time?
local const_eval = {}

local foldable_string_calls = {
   ["string.rep"] = true,
   ["string.sub"] = true,
   ["string.format"] = true,
   ["string.lower"] = true,
   ["string.upper"] = true,
   ["string.reverse"] = true,
   ["string.byte"] = true,
   ["tostring"] = true,
   ["tonumber"] = true,
}

-- An Op node is {operator, lhs, rhs} for a binary operator and {operator,
-- operand} for a unary one. Concatenation is left-associative in the parser,
-- so nested ".." simply nests on the left.
-- The parser names operators, not spells them: ".." is "concat".
local ARITH = {
   add = function(a, b) return a + b end,
   sub = function(a, b) return a - b end,
   mul = function(a, b) return a * b end,
   div = function(a, b) return a / b end,
   idiv = function(a, b) return math.floor(a / b) end,
   mod = function(a, b) return a % b end,
   pow = function(a, b) return a ^ b end,
}

local fold_local

-- The reaching-definition resolver for the fold in progress, or nil. A fold is synchronous and not
-- reentrant, so it is held here (and restored by the entry points) instead of being threaded through
-- every recursive call.
local active_reaching

local function fold(node, depth, seen)
   depth = depth or 0
   seen = seen or {}
   if depth > 32 or type(node) ~= "table" then
      return false, nil
   end

   local tag = node.tag
   if tag == "Number" then
      -- The parser keeps a number's source text, so a folded literal is a string
      -- unless it is converted here. Without this, arithmetic never folded and a
      -- number compared equal to its own text.
      return true, tonumber(node[1]) or node[1]
   elseif tag == "String" or tag == "Nil"
         or tag == "True" or tag == "False" then
      return true, node[1]
   elseif tag == "Paren" then
      return fold(node[1], depth + 1, seen)
   elseif tag == "Id" then
      return fold_local(node, depth + 1, seen)
   elseif tag == "Op" then
      local operator = node[1]
      local right_node = node[3]

      if not right_node then
         -- Unary: the value is the operand, so folding depends only on it.
         local ok, value = fold(node[2], depth + 1, seen)
         if not ok or operator ~= "unm" then return false, nil end
         if type(value) ~= "number" then return false, nil end
         return ok, -value
      end

      local ok_left, left = fold(node[2], depth + 1, seen)
      local ok_right, right = fold(right_node, depth + 1, seen)
      if not (ok_left and ok_right) then return false, nil end

      if operator == "concat" then
         if type(left) == "table" or type(right) == "table" then return false, nil end
         return true, tostring(left) .. tostring(right)
      end

      local fn = ARITH[operator]
      if not fn or type(left) ~= "number" or type(right) ~= "number" then return false, nil end
      local ok, value = pcall(fn, left, right)
      return ok, value
   elseif tag == "Call" then
      local callee = node[1]
      if not (callee and callee.tag == "Index" and callee[2] and callee[2].tag == "String") then
         return false, nil
      end
      local base = callee[1]
      if not (base and base.tag == "Id" and base[1] == "string" and not base.var) then
         return false, nil
      end
      local fname = callee[2][1]
      if not foldable_string_calls[fname] then return false, nil end
      return fold_call(fname, node, depth, seen)
   end

   return false, nil
end

-- Chase a local to its definition.
--
-- `resolve_locals` attaches the variable to every Id that reads it, and the
-- variable carries the list of values ever assigned to it. Folding follows that
-- list only when it is a single entry initialising the declaration itself: a
-- second assignment anywhere -- a reassignment in a branch, in a loop, or in a
-- closure -- makes the value at the use site unknown, and `701` fires on any
-- argument that is not provably constant, so giving up here is the whole point.
--
-- Only the declaration's own initialiser counts. `local X` followed by `X = "a"`
-- has one assignment, but it is not guaranteed to have run at the use site.
--
-- `seen` holds the variables already on this fold's path, so definitions that
-- name each other -- `local X = X` resolves the initialiser Id to the very
-- variable being resolved -- terminate instead of recursing.
--
-- A local bound to a table is not folded. `local M = {}; M.cmd = "lit"` needs a
-- write set for M to answer "is M.cmd still the literal", and writes through an
-- index, a metatable or a function are invisible to a per-variable reaching
-- definition. Table state stays dynamic, which is the safe direction.
fold_local = function(node, depth, seen)
   local var = node.var
   if not var or seen[var] then return false, nil end

   -- The definition that reaches THIS use, when the caller can name exactly one: a variable
   -- overwritten with a constant is that constant at the use, whatever it held before. The caller
   -- answers nil whenever it cannot be sure (several definitions reach, or one is written from a
   -- closure), and then the declaration-only rule below applies unchanged.
   local reaching = active_reaching and active_reaching(var)
   if reaching then
      seen[var] = true
      local ok, value = fold(reaching, depth, seen)
      seen[var] = nil
      return ok, value
   end

   local values = var.values
   if not values or #values ~= 1 then return false, nil end
   local definition = values[1]
   if not definition.node or definition.var_node ~= var.node then return false, nil end

   seen[var] = true
   local ok, value = fold(definition.node, depth, seen)
   seen[var] = nil
   return ok, value
end

-- Only the string library calls that take constant arguments are folded, and
-- results are length-capped so a crafted constant cannot make us allocate.
local MAX_FOLDED = 4096

local function fold_call(fname, node, depth, seen)
   local args = {}
   for i = 2, #node do
      local ok, value = fold(node[i], depth + 1, seen)
      if not ok then return false, nil end
      args[#args + 1] = value
   end

   if fname == "string.rep" then
      if type(args[1]) ~= "string" or type(args[2]) ~= "number" then return false, nil end
      if args[2] * #args[1] > MAX_FOLDED then return false, nil end
      return true, args[1]:rep(args[2])
   elseif fname == "string.format" then
      if type(args[1]) ~= "string" then return false, nil end
      local ok, result = pcall(string.format, unpack(args, 1, math.min(#args, 20)))
      if not ok or type(result) ~= "string" or #result > MAX_FOLDED then return false, nil end
      return true, result
   elseif fname == "tostring" then
      return true, tostring(args[1])
   elseif fname == "tonumber" then
      return true, tonumber(args[1])
   elseif fname == "string.reverse" then
      if type(args[1]) ~= "string" then return false, nil end
      return true, args[1]:reverse()
   elseif fname == "string.lower" then
      if type(args[1]) ~= "string" then return false, nil end
      return true, args[1]:lower()
   elseif fname == "string.upper" then
      if type(args[1]) ~= "string" then return false, nil end
      return true, args[1]:upper()
   end

   return false, nil
end

--- Is this expression's value known at parse time?
--- `reaching(var)` (optional) returns the one definition node that reaches the use, or nil.
function const_eval.is_constant(node, reaching)
   local saved = active_reaching
   active_reaching = reaching
   local ok_call, ok = pcall(fold, node, 0)
   active_reaching = saved
   if not ok_call then error(ok, 0) end
   return ok
end

--- Returns the folded value, or nil when the expression is not constant.
function const_eval.value(node, reaching)
   local saved = active_reaching
   active_reaching = reaching
   local ok_call, ok, value = pcall(fold, node, 0)
   active_reaching = saved
   if not ok_call then error(ok, 0) end
   if not ok then return nil end
   return value
end

return const_eval
