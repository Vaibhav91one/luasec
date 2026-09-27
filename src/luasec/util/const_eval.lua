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

local function fold(node, depth)
   depth = depth or 0
   if depth > 32 or type(node) ~= "table" then
      return false, nil
   end

   local tag = node.tag
   if tag == "String" or tag == "Number" or tag == "Nil"
         or tag == "True" or tag == "False" then
      return true, node[1]
   elseif tag == "Paren" then
      return fold(node[1], depth + 1)
   elseif tag == "Op" then
      local operator = node[1]
      local right_node = node[3]

      if not right_node then
         -- Unary: the value is the operand, so folding depends only on it.
         local ok, value = fold(node[2], depth + 1)
         if not ok or operator ~= "unm" then return false, nil end
         if type(value) ~= "number" then return false, nil end
         return ok, -value
      end

      local ok_left, left = fold(node[2], depth + 1)
      local ok_right, right = fold(right_node, depth + 1)
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
      return fold_call(fname, node, depth)
   end

   return false, nil
end

-- Only the string library calls that take constant arguments are folded, and
-- results are length-capped so a crafted constant cannot make us allocate.
local MAX_FOLDED = 4096

local function fold_call(fname, node, depth)
   local args = {}
   for i = 2, #node do
      local ok, value = fold(node[i], depth + 1)
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
function const_eval.is_constant(node)
   local ok = fold(node, 0)
   return ok
end

--- Returns the folded value, or nil when the expression is not constant.
function const_eval.value(node)
   local ok, value = fold(node, 0)
   if not ok then return nil end
   return value
end

return const_eval
