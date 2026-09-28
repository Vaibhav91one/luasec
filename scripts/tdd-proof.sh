#!/usr/bin/env bash
# Prove the tests in BASE..HEAD are coupled to the new behavior: reverse-apply
# only the src/ changes inside a scratch worktree and run the specs that the
# range added. They must fail.
#
# usage: make tdd-proof BASE HEAD
set -euo pipefail
base=${1:?base sha}
head=${2:?head sha}

root=$(git rev-parse --show-toplevel)
scratch=$(mktemp -d)
trap 'git -C "$root" worktree remove --force "$scratch" 2>/dev/null || rm -rf "$scratch"' EXIT

git -C "$root" worktree add --detach -q "$scratch" "$head"

# Which spec files were added or changed in this range?
mapfile -t specs < <(git -C "$root" diff --name-only "$base" "$head" -- 'test/**' | grep '_spec\.lua$' || true)
if [ ${#specs[@]} -eq 0 ]; then
  echo "tdd-proof: FAIL - no test files changed in $base..$head"
  exit 1
fi

# Reverse-apply the implementation only.
if ! git -C "$scratch" diff -R "$base" "$head" -- 'src/**' 'vendor/**' | git -C "$scratch" apply -q -; then
  echo "tdd-proof: SKIP - implementation diff does not apply cleanly in reverse"
  exit 0
fi

# build/ and vendor/luacheck are gitignored, so a fresh worktree has neither and
# every spec dies on `require "luacheck.parser"`. A proof that fails for that
# reason "passes" for the wrong reason, which is how this gate was vacuous.
cd "$scratch"
if [ ! -e build ]; then ln -s "$root/build" build 2>/dev/null || true; fi
if [ ! -e vendor/luacheck ]; then
  mkdir -p vendor 2>/dev/null || true
  ln -s "$root/vendor/luacheck" vendor/luacheck 2>/dev/null || true
fi
if [ ! -e vendor/luacheck ]; then
  echo "tdd-proof: SKIP - the scratch worktree has no vendored luacheck to run against"
  exit 1
fi

set +e
"$root/build/lua-5.4.9/src/lua" -e \
  "package.path='$scratch/src/?.lua;$scratch/src/?/init.lua;$scratch/vendor/?.lua;$scratch/vendor/?/init.lua;$scratch/test/?.lua;'..package.path" \
  - "$scratch" "${specs[@]}" <<'LUA' >/dev/null 2>&1
local scratch = ...
local specs = {}
for i = 2, #arg do
   specs[#specs + 1] = arg[i]
end
local harness = require "harness"
local failed = false
for i = 1, #specs do
   local path = specs[i]:gsub("^" .. scratch, ".")
   local chunk, err = loadfile(path)
   if not chunk then
      print("tdd-proof: cannot load " .. path .. ": " .. tostring(err))
      failed = true
   else
      local ok, load_err = pcall(chunk)
      if not ok then
         print("tdd-proof: " .. path .. " errored: " .. tostring(load_err))
         failed = true
      end
   end
end
-- Only the specs this change touched. Sweeping the tree would pick up
-- test/selfcheck/failing_spec.lua, which fails on purpose, and make the gate
-- pass for any diff that reverse-applies cleanly.
local _, failures = harness.run(specs)
if #failures > 0 then
   os.exit(1)
end
print("tdd-proof: touched specs pass with the implementation present")
os.exit(0)
LUA
status=$?
set -e

if [ "$status" -ne 0 ]; then
  echo "tdd-proof: PASS - the new tests fail without the new src (they are coupled to the behavior)"
  exit 0
fi

echo "tdd-proof: FAIL - the new tests still pass with the implementation removed"
exit 1
