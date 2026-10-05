#!/usr/bin/env bash
# Clone firmware and server-side Lua corpora for precision measurement. Network
# required; the results are gitignored and never committed.
#
# Three modes:
#
#   clone-corpus.sh [root]           clone what is missing, then verify
#   clone-corpus.sh --verify [root]  verify only, no network
#   clone-corpus.sh --list           print what the corpus is declared to hold
#
# --verify is the one that earns its keep. `make precision` freezes two file
# counts, so a corpus that lost a repository is caught - but as an arithmetic
# difference ("corpus holds 594 .lua files, the frozen measurement says 680"),
# which tells an operator that a number changed and nothing about which checkout
# went missing. Two failures the counts cannot catch at all:
#
#   * a pinned entry sitting at a revision other than its pin. The file count is
#     identical and the code is different, so the measurement describes a tree
#     that is no longer the tree. That is the "a corpus that changes under make
#     precision is a corpus that cannot be a measurement" case, and no count
#     sees it.
#   * an entry that cloned into an empty working tree - a checkout that ran and
#     produced nothing - where re-measuring gives a smaller number that looks
#     like a rule change.
#
# So verification names the entry, runs BEFORE the analyzer, and reports every
# problem rather than the first.
set -euo pipefail

mode=clone
case "${1:-}" in
  --verify) mode=verify; shift ;;
  --list)   mode=list;   shift ;;
esac
root=${1:-corpus}

# name|revision|minimum .lua files|what it is. One record per declared entry, and
# it is the only list: clone() appends to it, verify() and --list read it, so
# there is no second copy to fall out of step with the first.
CORPUS=()

clone() {
  local name=$1 url=$2 rev=${3:-} min_lua=${4:-0} what=${5:-}
  # Recorded before anything can return early: an entry that was already present
  # is still an entry `make corpus` promised, and --verify has to check it.
  CORPUS+=("$name|$rev|$min_lua|$what")

  if [ "$mode" != clone ]; then return 0; fi

  if [ -e "$root/$name/.git" ]; then
    # Re-check the pin on an existing tree: "already present" is not a promise
    # that it is the revision the numbers describe.
    if [ -n "$rev" ]; then
      local have
      have=$(git -C "$root/$name" rev-parse HEAD 2>/dev/null || echo none)
      if [ "$have" = "$rev" ]; then
        echo ">> $name already present at the pinned revision"
        return 0
      fi
      echo ">> $name is at $have, not the pinned $rev; fetching and checking out"
    else
      echo ">> $name already present"
      return 0
    fi
  fi
  echo ">> cloning $name${rev:+ at $rev}"
  mkdir -p "$(dirname "$root/$name")"
  if [ -n "$rev" ]; then
    # An existing tree at the wrong revision: clone cannot write into a
    # non-empty directory, so fetch and check out instead of re-cloning.
    if [ -e "$root/$name/.git" ]; then
      git -C "$root/$name" fetch --quiet origin \
        || { echo "!! could not fetch $name"; return 1; }
    else
      git clone --filter=blob:none "$url" "$root/$name" 2>/dev/null \
        || git clone "$url" "$root/$name" || { echo "!! failed: $name"; return 1; }
    fi
    git -C "$root/$name" checkout -q "$rev" 2>/dev/null \
      || echo "!! could not check out $rev for $name (numbers in docs/precision.md"
    # say which revision was measured)"
  else
    git clone --depth 1 "$url" "$root/$name" 2>/dev/null \
      || git clone "$url" "$root/$name" || { echo "!! failed: $name"; return 1; }
  fi
}

# ---------------------------------------------------------------- the corpora

# LuCI: the Lua web layer of OpenWrt, and our main source of real RCE history.
# Not pinned - a --depth 1 clone of the default branch. See "what is still
# unpinned" in docs/precision.md: the floor below is all that stands behind it.
clone luci https://github.com/openwrt/luci.git "" 1 "current LuCI libraries"

# The same web layer at openwrt-18.06, pinned. It is the largest part of the
# corpus and the part that is written as root-executing CGI, so a measurement
# taken only against current LuCI is a measurement against the safer code. The
# revision is pinned because a measurement is only reproducible against a
# revision: docs/precision.md quotes the number this one produced.
# Pinned to a commit, not to the branch: the branch moves, and a measurement
# against a moving branch is not a measurement. This is the commit
# docs/precision.md's 460-file count was taken on.
clone luci-1806 https://github.com/openwrt/luci.git 20b3600d4d64bf60588cf4975c7a62104411870e 1 \
  "LuCI at the 18.06 commit docs/precision.md's 460-file count was taken on"

# OpenWrt package tree, for the smaller scripts under package/. Contributes no
# .lua at all; the floor is 0 so the entry is still checked for existing and
# holding a working tree.
clone openwrt-packages https://github.com/openwrt/openwrt.git "" 0 \
  "the OpenWrt package tree, which contributes no .lua and is watched anyway"

# LuaJIT itself, for the FFI dialect.
clone luajit https://github.com/LuaJIT/LuaJIT.git "" 1 "LuaJIT, the firmware dialect"

# --- OpenResty, the server-side Lua profile --------------------------------
#
# Until these were added the corpus held no OpenResty at all: every source the
# openresty std declares is a firmware API, so no openresty source was in scope
# and a change to that profile could not move the number. #227, #240 and #263 all
# shipped such changes with a corpus figure of 0 before and 0 after, which is
# not evidence - it is the absence of a measurement. What is here is idiomatic
# server-side Lua, the libraries an OpenResty deployment actually loads, and the
# value of scanning it is catching false positives in code written by people who
# are not writing a firmware CGI script.
#
# Each is pinned to a released tag's commit, never to a branch. The tag is in
# the comment because it is the version a reader wants; the SHA is what is
# checked out because a tag can be moved and a commit cannot. These are upstream
# release trees, not deployed configuration.
clone lua-resty-core https://github.com/openresty/lua-resty-core.git 768ce9631dd91f864ba454af9615a81847c3230c 1 \
  "openresty/lua-resty-core v0.1.32, the FFI layer the openresty sinks are built on"
clone luasocket https://github.com/lunarmodules/luasocket.git 95b7efa9da506ef968c1347edf3fc56370f0deed 1 \
  "lunarmodules/luasocket v3.1.0, the socket/http/mime libraries OpenResty ships"
clone lua-resty-jwt https://github.com/cdbattags/lua-resty-jwt.git fc0ddeb009e42740506a848552631efc3a24a19e 1 \
  "cdbattags/lua-resty-jwt v0.3.2, a widely mirrored JWT handler: requests in, token out"
clone lua-cjson https://github.com/openresty/lua-cjson.git 5ce46a80b10ef9d380a45c9e6cff9ecffbe71ebb 1 \
  "openresty/lua-cjson 2.1.0.19, the JSON codec, over untrusted request bodies"
clone lua-nginx-module https://github.com/openresty/lua-nginx-module.git 4b21d8f5fd3cc94fd25c530b3a61405af9666d0b 1 \
  "openresty/lua-nginx-module v0.10.31, the ngx.* modules themselves"
clone lua-resty-lock https://github.com/openresty/lua-resty-lock.git 9dc550e56b6f3b1a2f1a31bb270a91813b5b6861 1 \
  "openresty/lua-resty-lock v0.09, shared-dict locking in one line of Lua"

# ---------------------------------------------------------------- verification

lua_count() { find "$1" -name '*.lua' -type f 2>/dev/null | wc -l | tr -d ' '; }

verify() {
  local problems=0 entry name rev min_lua what dir have
  for entry in "${CORPUS[@]}"; do
    IFS='|' read -r name rev min_lua what <<<"$entry"
    dir="$root/$name"

    if [ ! -d "$dir" ]; then
      echo "corpus-verify: FAIL  $name: $root/$name does not exist ($what)"
      echo "corpus-verify:       run \`make corpus\`. A measurement over $root without it"
      echo "corpus-verify:       describes a smaller corpus than the frozen numbers do"
      problems=$((problems + 1))
      continue
    fi

    if [ "$min_lua" -gt 0 ]; then
      have=$(lua_count "$dir")
      if [ "$have" -lt "$min_lua" ]; then
        echo "corpus-verify: FAIL  $name: $dir holds $have .lua files, expected at least $min_lua ($what)"
        echo "corpus-verify:       the checkout is empty or truncated. Delete it and run \`make corpus\`;"
        echo "corpus-verify:       do NOT re-measure and bless the smaller number - that is how the"
        echo "corpus-verify:       frozen figures drifted before"
        problems=$((problems + 1))
        continue
      fi
    fi

    if [ -n "$rev" ]; then
      # -e, not -d: a git worktree's .git is a file pointing at the real gitdir,
      # and `[ -d ]` on it says "not a checkout" about a perfectly good one.
      if [ ! -e "$dir/.git" ]; then
        echo "corpus-verify: FAIL  $name: $dir has no .git, so its pin ($rev) cannot be checked ($what)"
        echo "corpus-verify:       a pinned entry that cannot be checked is a measurement nobody can repeat"
        problems=$((problems + 1))
        continue
      fi
      have=$(git -C "$dir" rev-parse HEAD 2>/dev/null || echo none)
      if [ "$have" != "$rev" ]; then
        echo "corpus-verify: FAIL  $name: $dir is at $have, not the pinned $rev ($what)"
        echo "corpus-verify:       docs/precision.md's numbers were taken on the pinned tree. Run"
        echo "corpus-verify:       \`make corpus\` to check it out again, or re-pin deliberately and re-measure"
        problems=$((problems + 1))
        continue
      fi
    fi

    echo "corpus-verify: ok    $name${rev:+ @ ${rev:0:12}}  $(lua_count "$dir") .lua  - $what"
  done

  if [ "$problems" -gt 0 ]; then
    echo "corpus-verify: FAILED - $problems of ${#CORPUS[@]} declared entries are not what"
    echo "corpus-verify:          clone-corpus.sh says they are. The measurement below would"
    echo "corpus-verify:          describe a different corpus than the frozen numbers."
    return 1
  fi
  echo "corpus-verify: ok - all ${#CORPUS[@]} declared entries present, non-empty, and at their pins"
}

case "$mode" in
  list)
    printf '%s\n' "${CORPUS[@]}"
    ;;
  verify)
    verify
    ;;
  clone)
    mkdir -p "$root"
    echo
    echo "corpora under $root:"
    for d in "$root"/*/; do
      [ -d "$d" ] || continue
      printf '  %-40s %s lua files\n' "$(basename "$d")" "$(lua_count "$d")"
    done
    echo
    verify
    ;;
esac