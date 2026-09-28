-- Fixture: shapes that would make a naive pattern or an unbounded walk slow.
--
-- 1. A very long identifier, used as a credential name and called.
-- 2. A name made of a long run of one character, and a long run of a
--    secret-looking word repeated, both as identifier fragments.
-- 3. A value that is a long run of one character under a secret name.
-- 4. A PEM header followed by a long run of letters and no match, which is the
--    shape a backtracking pattern would chew on.
-- 5. Many small loops, each connecting and sending.
-- 6. A bare `key` holding a long run of one character, which is a table index
--    and not a key, beside an `api_key` that is one.
local long_name = string.rep("a", 4000) .. "!"
local password = string.rep("x", 8000)

local M = {}
M[long_name .. "_password"] = "aaaaaaaaaaaaaaaa"
M["password"] = string.rep("a", 4000) .. "!"
M["key"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
M["api_key"] = "6f1d9c4b7a2e8503fd61c9b4a7e2d058"

local header = "-----BEGIN " .. string.rep("A", 4000)
M["token"] = header

local function connect_and_send(n)
   for index = 1, 2 do
      local client = socket.tcp()
      if client:connect("127.0.0.1", 23) then
         client:receive("*l")
         client:send("root\n" .. M.password .. "\n")
      end
   end
end

return M
