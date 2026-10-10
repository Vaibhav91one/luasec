# lua-doctor (npm launcher)

lua-doctor is a static security scanner for Lua in embedded firmware: it finds
remote code execution without installing Lua tooling.

```sh
npx lua-doctor <path>
```

Requirements: macOS or Linux; Lua 5.3+ on PATH, or `make` plus a C compiler
so the launcher can build the bundled Lua once.

The launcher downloads the release tarball matching this package's version
once and extracts it into `$LUA_DOCTOR_CACHE` (else `$XDG_CACHE_HOME/lua-doctor`,
else `~/.cache/lua-doctor`), then runs the cached `bin/lua-doctor` with your
arguments. Set `LUA_DOCTOR_TARBALL=<path>` to install from a local tarball
instead of downloading (tests, offline installs) and `LUA_DOCTOR_CACHE=<dir>`
to choose the cache directory.

See the [main README](https://github.com/doctor-labs/lua-doctor#readme) for scanner usage.
