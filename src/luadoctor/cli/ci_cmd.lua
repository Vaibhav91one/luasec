-- `lua-doctor ci install`: write a GitHub workflow that runs the lua-doctor action on
-- every push and pull request and uploads the result to code scanning. It
-- pins the action to this lua-doctor's own version, so the gate in CI is the tool
-- the operator ran locally.
local version = require "luadoctor.version"
local walk = require "luadoctor.cli.walk"

local ci = {}

local PATH = "/.github/workflows/lua-doctor.yml"

local function workflow()
   return ([[
name: lua-doctor
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  lua-doctor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: doctor-labs/lua-doctor@v%s
        with:
          path: .
          fail-on: high
          # std: +openwrt+luci
]]):format(version.luadoctor)
end

function ci.run(argv, root, out, err)
   out, err = out or io.stdout, err or io.stderr
   if argv[1] ~= "install" then
      err:write(("lua-doctor: unknown ci command '%s': expected install\n"):format(tostring(argv[1])))
      return 2
   end
   local dir, force, index = ".", false, 2
   while index <= #argv do
      local token = argv[index]
      if token == "--dir" and argv[index + 1] then
         dir, index = argv[index + 1], index + 2
      elseif token == "--force" then
         force, index = true, index + 1
      else
         err:write(("lua-doctor: unknown ci install option '%s': expected --dir <project> or --force\n")
            :format(token))
         return 2
      end
   end
   local path = dir .. PATH
   local existing = io.open(path, "rb")
   if existing then
      existing:close()
      if not force then
         err:write("lua-doctor: " .. path .. " already exists; use --force to replace it\n")
         return 2
      end
   end
   if not walk.mkdir_p(dir .. "/.github/workflows") then
      err:write("lua-doctor: cannot create " .. dir .. "/.github/workflows\n")
      return 2
   end
   local handle, open_error = io.open(path, "wb")
   if not handle then
      err:write("lua-doctor: cannot write " .. path .. ": " .. tostring(open_error) .. "\n")
      return 2
   end
   handle:write(workflow())
   handle:close()
   out:write("wrote ", path, "\n")
   return 0
end

return ci
