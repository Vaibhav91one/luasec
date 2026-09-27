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

local function fold(node, depth)
   depth = depth or 0
   if depth > 8 or type(node) ~= "table" then
      return false, nil
   end

   local tag = node.tag
   if tag == "String" or tag == "Number" or tag == "Nil"
         or tag == "True" or tag == "False" then
      return true, node[1]
   elseif tag == "Paren" then
      return fold(node[1], depth + 1)
   elseif tag == "Op" then
      local operator = node[2]
      if operator == ".." then
         local ok_left, left = fold(node[3] or node[2], depth + 1)
         if not ok_left then
            -- ".." is left-associative: the right operand is the tail.
            return false, nil
         end
         -- Walk left through the concatenation chain.
         local current = node
         while current and current.tag == "Op" and current[2] == ".." do
            local head_ok, head = fold(current[3] or current[2], 0)
            if not head_ok then return false, nil end
            left = tostring(head) .. tostring(left)
            current = current.parent
         end
         return true, left
      elseif operator == "+" or operator == "-" or operator == "*"
            or operator == "/" or operator == "^" or operator == "%" then
         local ok_left, left = fold(node[3] or node[2], depth + 1)
         local ok_right, right = fold(node[4] or node[3], depth + 1)
         if not (ok_left and ok_right) then return false, nil end
         local fn = ({["+"] = function(a, b) return a + b end, ["-"] = function(a, b) return a - b end,
                      ["*"] = function(a, b) return a * b end, ["/"] = function(a, b) return a / b end,
                      ["^"] = function(a, b) return a ^ b end, ["%"] = function(a, b) return a % b end})[operator]
         if not fn or type(left) ~= "number" or type(right) ~= "number" then return false, nil end
         local ok, value = pcall(fn, left, right)
         return ok, value
      end
      return false, nil
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
