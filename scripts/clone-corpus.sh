#!/usr/bin/env bash
# Clone firmware Lua corpora for precision measurement. Network required; the
# results are gitignored and never committed.
set -euo pipefail
root=${1:-corpus}
mkdir -p "$root"

clone() {
  local name=$1 url=$2 rev=${3:-}
  if [ -d "$root/$name/.git" ]; then
    # Re-check the pin on an existing tree: "already present" is not a promise
    # that it is the revision the numbers describe.
    if [ -n "$rev" ]; then
      local have
      have=$(git -C "$root/$name" rev-parse HEAD 2>/dev/null || echo none)
      if [ "$have" = "$rev" ]; then
        echo ">> $name already present at the pinned revision"
        return 0
      fi
      echo ">> $name is at $have, not the pinned $rev; re-checking out"
    else
      echo ">> $name already present"
      return 0
    fi
  fi
  echo ">> cloning $name${rev:+ at $rev}"
  if [ -n "$rev" ]; then
    # A pinned revision, and a shallow clone cannot check one out: fetch the
    # depth that contains it, or fetch the whole history.
    git clone --filter=blob:none "$url" "$root/$name" 2>/dev/null \
      || git clone "$url" "$root/$name" || { echo "!! failed: $name"; return 0; }
    git -C "$root/$name" checkout -q "$rev" 2>/dev/null \
      || echo "!! could not check out $rev for $name (numbers in docs/precision.md"
    # say which revision was measured)"
  else
    git clone --depth 1 "$url" "$root/$name" 2>/dev/null \
      || git clone "$url" "$root/$name" || { echo "!! failed: $name"; return 0; }
  fi
}

# LuCI: the Lua web layer of OpenWrt, and our main source of real RCE history.
clone luci https://github.com/openwrt/luci.git

# The same web layer at openwrt-18.06, pinned. It is the largest part of the
# corpus and the part that is written as root-executing CGI, so a measurement
# taken only against current LuCI is a measurement against the safer code. The
# revision is pinned because a measurement is only reproducible against a
# revision: docs/precision.md quotes the number this one produced.
# Pinned to a commit, not to the branch: the branch moves, and a measurement
# against a moving branch is not a measurement. This is the commit
# docs/precision.md's 460-file count was taken on.
clone luci-1806 https://github.com/openwrt/luci.git 20b3600d4d64bf60588cf4975c7a62104411870e

# OpenWrt package tree, for the smaller scripts under package/.
clone openwrt-packages https://github.com/openwrt/openwrt.git

# LuaJIT itself, for the FFI dialect.
clone luajit https://github.com/LuaJIT/LuaJIT.git

echo "corpora under $root:"
for d in "$root"/*/; do
  [ -d "$d" ] || continue
  printf '  %-40s %s lua files\n' "$(basename "$d")" \
    "$(find "$d" -name '*.lua' -type f 2>/dev/null | wc -l | tr -d ' ')"
done
