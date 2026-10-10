#!/bin/sh
# Build the release tarball: every tracked file plus the vendored luacheck, under
# lua-doctor-<version>/. The rockspec, the npm launcher and the Homebrew formula all
# install from this one file. Run `make vendor` first.
set -eu
cd "$(dirname "$0")/.."
version=$(sed -n 's/^ *luasec = "\(.*\)",$/\1/p' src/luasec/version.lua)
[ -n "$version" ] || { echo "release-tarball: no version in src/luasec/version.lua" >&2; exit 1; }
[ -f vendor/luacheck/.stamp ] || { echo "release-tarball: run make vendor first" >&2; exit 1; }
name="lua-doctor-$version"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name" dist
{ git ls-files; find vendor/luacheck -type f; } | sort -u | while IFS= read -r file; do
  mkdir -p "$stage/$name/$(dirname "$file")"
  cp -p "$file" "$stage/$name/$file"
done
tar czf "dist/$name.tar.gz" -C "$stage" "$name"
echo "dist/$name.tar.gz"
