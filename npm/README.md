# luasec (npm launcher)

luasec is a static security scanner for Lua in embedded firmware: it finds
remote code execution without installing Lua tooling.

```sh
npx luasec <path>
```

Requirements: macOS or Linux; Lua 5.3+ on PATH, or `make` plus a C compiler
so the launcher can build the bundled Lua once.

The launcher downloads the release tarball matching this package's version
once and extracts it into `$LUASEC_CACHE` (else `$XDG_CACHE_HOME/luasec`,
else `~/.cache/luasec`), then runs the cached `bin/luasec` with your
arguments. Set `LUASEC_TARBALL=<path>` to install from a local tarball
instead of downloading (tests, offline installs) and `LUASEC_CACHE=<dir>`
to choose the cache directory.

See the [main README](https://github.com/Vaibhav91one/luasec#readme) for scanner usage.
