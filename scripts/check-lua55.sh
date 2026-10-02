#!/bin/sh
# Compile every .lua under src/ with a Lua 5.5 interpreter and fail on any error.
# 5.5 refuses code 5.4 accepts (assigning to a for-loop variable, #174), and every
# other check runs on the 5.4 this repo builds, so this is the only one that sees it.
# Without a 5.5 on PATH it skips with a notice locally, and fails in CI ($CI set).
set -e
for candidate in "${LUA55:-}" lua5.5 lua; do
  [ -n "$candidate" ] || continue
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -v 2>&1 | grep -q '^Lua 5\.5'; then
    lua=$candidate
    break
  fi
done
if [ -z "$lua" ]; then
  if [ -n "$CI" ]; then
    echo "lua55-check: FAIL - no Lua 5.5 interpreter on PATH (set LUA55)"; exit 1
  fi
  echo "lua55-check: SKIPPED - no Lua 5.5 interpreter on PATH (set LUA55 to run it)"; exit 0
fi
# `lua -` runs the script from stdin and passes it the file names as arguments
# (src/ paths have no spaces, so word splitting is safe).
"$lua" - $(find src -name '*.lua' | sort) <<'LUA'
local bad = 0
for _, path in ipairs(arg) do
   local ok, err = loadfile(path)
   if not ok then
      print(err)
      bad = bad + 1
   end
end
if bad > 0 then
   print(("lua55-check: FAIL - %d file(s) do not compile under %s"):format(bad, _VERSION))
   os.exit(1)
end
print(("lua55-check: ok (%d files compile under %s)"):format(#arg, _VERSION))
LUA
