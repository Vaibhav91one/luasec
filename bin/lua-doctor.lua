-- The lua-doctor command as LuaRocks installs it. The modules are already on
-- package.path; the doc pages (docs/rules) are copied into the rock's own
-- directory, which is where LuaRocks keeps this script too, one level down.
LUA_DOCTOR_ROOT = (arg and arg[0] or ""):match("^(.*)/bin/[^/]*$") or "."
require "luasec.main"
