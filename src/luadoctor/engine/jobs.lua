-- `--jobs N`: a per-file scan split over N child interpreters.
--
-- Lua has no threads, so a worker is a child process: the same interpreter
-- (`$LUA_DOCTOR_LUA`, which bin/lua-doctor exports) running `api.analyze` over a
-- contiguous slice of the file list and writing its findings back as a Lua
-- table. Slices are contiguous and collected in order, so the parent sees the
-- findings in the same order a serial run produces them, and the report is
-- sorted on a total order after that: `--jobs 1` and `--jobs 8` write the same
-- bytes.
local jobs = {}

local function shell_quote(text)
   return "'" .. tostring(text):gsub("'", "'\\''") .. "'"
end

-- Data only: strings, numbers, booleans and tables of them. A function (the
-- progress callbacks) has no meaning in another process and is dropped, and so
-- is a table met a second time on the way down, so a cycle cannot recurse forever.
local function serialize(value, out, seen)
   seen = seen or {}
   local kind = type(value)
   if kind == "string" then
      out[#out + 1] = ("%q"):format(value)
   elseif kind == "number" then
      out[#out + 1] = math.type(value) == "integer" and tostring(value) or ("%.17g"):format(value)
   elseif kind == "boolean" then
      out[#out + 1] = tostring(value)
   elseif kind == "table" and not seen[value] then
      seen[value] = true
      out[#out + 1] = "{"
      for key, item in pairs(value) do
         local item_kind = type(item)
         if item_kind ~= "function" and item_kind ~= "userdata" and item_kind ~= "thread" then
            out[#out + 1] = "["
            serialize(key, out, seen)
            out[#out + 1] = "]="
            serialize(item, out, seen)
            out[#out + 1] = ","
         end
      end
      out[#out + 1] = "}"
      seen[value] = nil
   else
      out[#out + 1] = "nil"
   end
   return out
end

local function write_file(path, text)
   local handle = assert(io.open(path, "wb"))
   handle:write(text)
   handle:close()
end

local function read_value(path)
   local handle = io.open(path, "rb")
   if not handle then return nil end
   local text = handle:read("a")
   handle:close()
   -- lua-doctor: ignore 710  a file this run wrote to a fresh os.tmpname(), loaded as text in an empty environment
   local chunk = load(text, "=" .. path, "t", {})
   if not chunk then return nil end
   local ok, value = pcall(chunk)
   return ok and value or nil
end

-- The interpreter running us: `$LUA_DOCTOR_LUA` from bin/lua-doctor, else the
-- lowest-indexed entry of `arg`, which is where the standalone interpreter puts
-- its own path (a LuaRocks or npm launcher does not export the variable).
local function interpreter()
   local lua = os.getenv("LUA_DOCTOR_LUA")
   if lua and lua ~= "" then return lua end
   if type(arg) ~= "table" then return nil end
   local lowest = 0
   while arg[lowest - 1] ~= nil do lowest = lowest - 1 end
   return lowest < 0 and arg[lowest] or nil
end

--- How many workers a run gets: `opts.jobs`, or 1 when the run cannot be
-- split (whole-program analysis needs every file in one process, and without
-- an interpreter path there is nothing to start).
function jobs.count(opts, file_count)
   local wanted = tonumber(opts.jobs) or 1
   if wanted <= 1 or opts.whole_program or file_count < 2 or not interpreter() then
      return 1
   end
   return math.min(wanted, file_count)
end

--- Analyze `paths` in `workers` child processes. `analyze(paths, opts)` returns
-- a slice's findings and its store writes without pairing them, and is used in
-- this process for a slice whose worker failed, so a crashed worker costs time
-- and never findings. `notify(done, total, path)` reports progress. Returns the
-- findings and the store writes of every slice; the caller pairs them.
function jobs.run(paths, opts, workers, analyze, notify)
   local lua = interpreter()
   local child_opts = {}
   for key, value in pairs(opts) do child_opts[key] = value end
   -- Progress is reported here, per slice, so a slice analyzed in this process
   -- after its worker died does not report its files a second time.
   child_opts.jobs, child_opts.on_file, child_opts.on_phase = nil, nil, nil
   local opts_text = "return " .. table.concat(serialize(child_opts, {}))

   -- Four slices per worker, so one slow slice does not hold the others idle.
   local size = math.max(1, math.ceil(#paths / (workers * 4)))
   local slices = {}
   for first = 1, #paths, size do
      local slice = {}
      for index = first, math.min(first + size - 1, #paths) do slice[#slice + 1] = paths[index] end
      slices[#slices + 1] = slice
   end

   local function start(slice)
      local job = {slice = slice, input = os.tmpname(), output = os.tmpname()}
      write_file(job.input, "return " .. table.concat(serialize({paths = slice, opts = opts_text}, {})))
      -- `lua -e` passes no arguments to its chunk, so the two paths are in the code.
      local boot = ("package.path=%q;require('luadoctor.engine.jobs').child(%q,%q)")
         :format(package.path, job.input, job.output)
      -- lua-doctor: ignore 709  the interpreter running lua-doctor, with every fragment shell_quote()d
      job.pipe = io.popen(shell_quote(lua) .. " -e " .. shell_quote(boot) .. " 2>/dev/null")
      return job
   end

   local findings, writes, running, next_slice, done = {}, {}, {}, 1, 0
   while next_slice <= #slices or #running > 0 do
      while #running < workers and next_slice <= #slices do
         running[#running + 1] = start(slices[next_slice])
         next_slice = next_slice + 1
      end
      local job = table.remove(running, 1)
      job.pipe:read("a")
      job.pipe:close()
      local result = read_value(job.output)
      os.remove(job.input)
      os.remove(job.output)
      if type(result) ~= "table" or type(result.findings) ~= "table" then
         -- The worker died (a crash, a kill, an interpreter that would not
         -- start): its slice is analyzed here instead, where a file that breaks
         -- the engine is one 901 like in any serial run.
         local slice_findings, slice_writes = analyze(job.slice, child_opts)
         result = {findings = slice_findings, writes = slice_writes}
      end
      for _, finding in ipairs(result.findings) do findings[#findings + 1] = finding end
      for _, write in ipairs(result.writes or {}) do writes[#writes + 1] = write end
      done = done + #job.slice
      notify(done, #paths, job.slice[#job.slice])
   end
   return findings, writes
end

--- The child's side: analyze the slice in `input`, write the findings to `output`.
function jobs.child(input, output)
   local job = read_value(input)
   -- lua-doctor: ignore 703  the options the parent serialized, loaded as text in an empty environment
   local opts = load(job.opts, "=opts", "t", {})()
   local api = require "luadoctor.api"
   -- The registries (--std, --rules) are installed by validate_options, which
   -- the parent ran before the scan; this process has to do the same.
   assert(api.validate_options(opts))
   -- Unpaired: a store write in one slice can pair with a read in another, so
   -- the parent pairs once every slice is back.
   local findings, writes = api.analyze_unpaired(job.paths, opts)
   write_file(output, "return " .. table.concat(serialize({findings = findings, writes = writes}, {})))
end

return jobs
