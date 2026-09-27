# vendor/

`vendor/luacheck/` is an unmodified copy of `src/luacheck/` from
lunarmodules/luacheck at the sha recorded in `vendor/PINNED`.

Never edit it. `make vendor-verify` recomputes `vendor/MANIFEST.sha256` and
fails if anything drifted; `make vendor` restores it.
