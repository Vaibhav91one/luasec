#!/usr/bin/env bash
# Clone firmware Lua corpora for precision measurement. Network required; the
# results are gitignored and never committed.
set -euo pipefail
root=${1:-corpus}
mkdir -p "$root"

clone() {
  local name=$1 url=$2 rev=${3:-}
  if [ -d "$root/$name/.git" ]; then
    echo ">> $name already present"
  else
    echo ">> cloning $name"
    git clone --depth "${rev:+1}" "$url" "$root/$name" 2>/dev/null \
      || git clone "$url" "$root/$name" || { echo "!! failed: $name"; return 0; }
  fi
}

# LuCI: the Lua web layer of OpenWrt, and our main source of real RCE history.
clone luci https://github.com/openwrt/luci.git

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
