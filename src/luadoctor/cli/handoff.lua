-- Agent hand-off submenu, reached from the terminal menu's `f` action. It
-- never skips the agent's approval prompts from here: every launch goes
-- through fix.run with --safe, and the default answers print the prompt.
local fix_cmd = require "luadoctor.cli.fix_cmd"
local selector = require "luadoctor.cli.selector"
local term = require "luadoctor.cli.term"

local handoff = {}

local AGENTS = {
   {name = "claude", label = "Claude Code", bin = "claude", key = "c"},
   {name = "codex", label = "Codex", bin = "codex", key = "x"},
   {name = "cursor", label = "Cursor", bin = "cursor-agent", key = "u"},
}

local CLIPBOARDS = {
   pbcopy = "pbcopy",
   ["wl-copy"] = "wl-copy",
   xclip = "xclip -selection clipboard",
   xsel = "xsel --clipboard --input",
}

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function base64(text)
   local out = {}
   for first = 1, #text, 3 do
      local a, b, c = text:byte(first, first + 2)
      local n = a * 65536 + (b or 0) * 256 + (c or 0)
      local s1, s2 = math.floor(n / 262144) % 64, math.floor(n / 4096) % 64
      local s3, s4 = math.floor(n / 64) % 64, n % 64
      out[#out + 1] = B64:sub(s1 + 1, s1 + 1) .. B64:sub(s2 + 1, s2 + 1)
      if b == nil then
         out[#out + 1] = "=="
      elseif c == nil then
         out[#out + 1] = B64:sub(s3 + 1, s3 + 1) .. "="
      else
         out[#out + 1] = B64:sub(s3 + 1, s3 + 1) .. B64:sub(s4 + 1, s4 + 1)
      end
   end
   return table.concat(out)
end

--- The OSC 52 escape sequence carrying `text` to the terminal clipboard.
function handoff.osc52(text)
   return "\27]52;c;" .. base64(text) .. "\7"
end

--- The first clipboard tool on PATH, or nil. Pure enough to test with a
-- restricted PATH: each probe is a constant `command -v` for a fixed tool.
function handoff.clipboard_command()
   -- lua-doctor: ignore 701  the command -v probes are constant tool names, never user input
   if os.execute("command -v pbcopy >/dev/null 2>&1") then return "pbcopy" end
   -- lua-doctor: ignore 701  the command -v probes are constant tool names, never user input
   if os.execute("command -v wl-copy >/dev/null 2>&1") then return "wl-copy" end
   -- lua-doctor: ignore 701  the command -v probes are constant tool names, never user input
   if os.execute("command -v xclip >/dev/null 2>&1") then return "xclip" end
   -- lua-doctor: ignore 701  the command -v probes are constant tool names, never user input
   if os.execute("command -v xsel >/dev/null 2>&1") then return "xsel" end
   return nil
end

local function flush(out)
   if out.flush then out:flush() end
end

-- lua-doctor: ignore 708  the stty commands are constant mode switches, never user input
local function read_line(context, tty, prompt)
   context.out:write(prompt)
   flush(context.out)
   if tty then os.execute("stty icanon echo isig") end
   local line = io.read("*l")
   if tty then os.execute("stty -icanon -echo -isig min 1") end
   return line
end

local function trim(text)
   return text:match("^%s*(.-)%s*$")
end

local function quote(text)
   return "'" .. tostring(text):gsub("'", "'\\''") .. "'"
end

local function do_copy(context, prompt)
   local tool = handoff.clipboard_command()
   if tool then
      local tmp = os.tmpname()
      local handle = io.open(tmp, "wb")
      if not handle then
         context.out:write("lua-doctor: cannot copy the prompt\n")
         return
      end
      handle:write(prompt)
      handle:close()
      -- lua-doctor: ignore 701  the clipboard command is from the fixed table and reads a temp file, never the prompt
      os.execute(CLIPBOARDS[tool] .. " < " .. quote(tmp))
      os.remove(tmp)
      context.out:write("copied with " .. tool .. "\n")
   else
      context.out:write(handoff.osc52(prompt) .. "\n")
      context.out:write("copied with the terminal (OSC 52)\n")
   end
end

local function prompt_or_warn(list, context)
   local prompt, message = fix_cmd.prompt_for(context.argv or {}, context.root or ".")
   if not prompt then
      context.out:write("lua-doctor: " .. tostring(message) .. "\n")
      _ = list
      return nil
   end
   return prompt
end

--- The `f` action's body: pick an installed agent, copy or show the fix
-- prompt, or go back. Launches always keep approvals on (--safe); anything
-- but an explicit `y` prints the prompt instead of launching.
function handoff.run(list, context, tty)
   context.out = context.out or io.stdout
   context.err = context.err or io.stderr
   local installed = {}
   -- lua-doctor: ignore 701  the command -v probe is a constant agent name, never user input
   installed.claude = os.execute("command -v claude >/dev/null 2>&1") and true or false
   -- lua-doctor: ignore 701  the command -v probe is a constant agent name, never user input
   installed.codex = os.execute("command -v codex >/dev/null 2>&1") and true or false
   -- lua-doctor: ignore 701  the command -v probe is a constant agent name, never user input
   installed.cursor = os.execute("command -v cursor-agent >/dev/null 2>&1") and true or false
   local items = {}
   for _, agent in ipairs(AGENTS) do
      items[#items + 1] = {key = agent.key, label = agent.label,
         note = (not installed[agent.name]) and "not installed" or nil}
   end
   local copy_at = #items + 1
   items[#items + 1] = {key = "y", label = "Copy prompt"}
   items[#items + 1] = {key = "w", label = "Show prompt"}
   items[#items + 1] = {key = "b", label = "Back"}
   local recommended = copy_at
   for index, agent in ipairs(AGENTS) do
      if installed[agent.name] then
         recommended = index
         break
      end
   end
   for index, item in ipairs(items) do
      item.recommended = (index == recommended)
   end
   while true do
      local picked = selector.pick(context, "Hand these findings to an agent",
         items, {initial = recommended})
      if picked == nil then return end
      recommended = picked
      for index, item in ipairs(items) do
         item.recommended = (index == recommended)
      end
      local item = items[picked]
      if item.key == "b" then
         return
      elseif item.key == "y" then
         local prompt = prompt_or_warn(list, context)
         if prompt then do_copy(context, prompt) end
      elseif item.key == "w" then
         local prompt = prompt_or_warn(list, context)
         if prompt then context.out:write(prompt .. "\n") end
      else
         local agent = AGENTS[picked]
         context.out:write("The scanned code is untrusted. The agent runs with its "
            .. "approval prompts ON; nothing is changed until you approve each action.\n")
         local answer = read_line(context, tty, ("Launch %s? [y/N] "):format(agent.name))
         if answer == nil then return end
         local fargv = {"--agent", agent.name, "--safe"}
         for _, token in ipairs(context.argv or {}) do fargv[#fargv + 1] = token end
         if trim(answer):lower() ~= "y" then fargv[#fargv + 1] = "--print" end
         fix_cmd.run(fargv, context.root or ".", context.out, context.err)
      end
      flush(context.out)
   end
end

return handoff
