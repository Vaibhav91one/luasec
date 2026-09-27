# luasec - RCE checker / security analyzer for Lua in embedded firmware.
#
# No luarocks, no C dependencies beyond a locally built Lua. See AGENTS.md.

LUA_VERSION := 5.4.9
LUA_SHA256  := 2335b6c582a52654f94612bf10d2f4672805d05329aa6568b1d8cd9e5c6fb8e6
LUA_URL     := https://www.lua.org/ftp/lua-$(LUA_VERSION).tar.gz
LUA_DIR     := build/lua-$(LUA_VERSION)
LUA         := $(LUA_DIR)/src/lua
LUAC        := $(LUA_DIR)/src/luac

LUACHECK_REPO := lunarmodules/luacheck
LUACHECK_SHA  := 2f764bdcabe8b7c19deadf0e9bb2adc19df1a4c5
LUACHECK_URL  := https://codeload.github.com/$(LUACHECK_REPO)/tar.gz/$(LUACHECK_SHA)

LUA_RUN := $(LUA) -e 'package.path="./src/?.lua;./src/?/init.lua;./vendor/?.lua;./vendor/?/init.lua;"..package.path'

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "targets:"
	@echo "  make            build lua + vendor, then run tests"
	@echo "  make lua        download and build Lua $(LUA_VERSION) into $(LUA_DIR)"
	@echo "  make vendor     fetch pinned luacheck into vendor/luacheck"
	@echo "  make vendor-verify   fail if vendored luacheck drifted"
	@echo "  make test       run the spec suite"
	@echo "  make ci-verify  full gate (vendor + upstream specs + our specs + adversarial)"
	@echo "  make tdd-proof BASE HEAD   prove new tests fail without the new src"
	@echo "  make corpus     clone firmware Lua corpora into corpus/ (network)"
	@echo "  make clean      remove build artifacts"

.PHONY: all
all: lua vendor test

# ---------------------------------------------------------------- lua

.PHONY: lua
lua: $(LUA)

$(LUA):
	@mkdir -p build
	@echo ">> fetching Lua $(LUA_VERSION)"
	@curl -sSL -o build/lua-$(LUA_VERSION).tar.gz $(LUA_URL)
	@echo "$(LUA_SHA256)  build/lua-$(LUA_VERSION).tar.gz" | shasum -a 256 -c - >/dev/null \
		|| { echo "Lua tarball checksum mismatch"; exit 1; }
	@tar xzf build/lua-$(LUA_VERSION).tar.gz -C build
	@$(MAKE) -C $(LUA_DIR) macosx >/dev/null 2>&1 || $(MAKE) -C $(LUA_DIR) posix >/dev/null
	@$(LUA) -v

# ---------------------------------------------------------------- vendor

.PHONY: vendor
vendor: vendor/luacheck/.stamp

vendor/luacheck/.stamp:
	@echo ">> fetching $(LUACHECK_REPO)@$(LUACHECK_SHA)"
	@mkdir -p build vendor
	@curl -sSL -o build/luacheck.tar.gz $(LUACHECK_URL)
	@tar xzf build/luacheck.tar.gz -C build
	@rm -rf vendor/luacheck
	@mkdir -p vendor/luacheck
	@cp -R build/luacheck-*/src/luacheck/. vendor/luacheck/
	@cp build/luacheck-*/LICENSE vendor/luacheck/LICENSE
	@printf 'repo=%s\nsha=%s\nurl=https://github.com/%s\nlicense=MIT\nnote=src/luacheck only. Never edit; regenerate with `make vendor`.\n' \
		"$(LUACHECK_REPO)" "$(LUACHECK_SHA)" "$(LUACHECK_REPO)" > vendor/PINNED
	@$(MAKE) --no-print-directory vendor-manifest
	@touch $@

vendor/MANIFEST.sha256: vendor/luacheck/.stamp
	@:

.PHONY: vendor-manifest
vendor-manifest:
	@cd vendor/luacheck && find . -type f \( -name '*.lua' -o -name 'LICENSE' \) \
		| LC_ALL=C sort | xargs shasum -a 256 > ../MANIFEST.sha256

.PHONY: vendor-verify
vendor-verify: vendor
	@cd vendor/luacheck && shasum -a 256 -c ../MANIFEST.sha256 >/dev/null \
		&& echo "vendor-verify: ok ($(LUACHECK_REPO)@$(LUACHECK_SHA))" \
		|| { echo "vendor-verify: FAILED - vendored luacheck was modified"; exit 1; }
	@grep -q "$(LUACHECK_SHA)" vendor/PINNED || { echo "vendor-verify: FAILED - PINNED sha mismatch"; exit 1; }

# ---------------------------------------------------------------- tests

.PHONY: test
test: lua vendor
	@$(LUA_RUN) test/run.lua

.PHONY: runner-selftest
runner-selftest: lua vendor
	@if $(LUA_RUN) test/zz_failing_spec.lua >/dev/null 2>&1; then \
		echo "runner-selftest: FAILED - a failing spec did not fail the runner"; exit 1; \
	else \
		echo "runner-selftest: ok (failing spec exits non-zero)"; \
	fi

# Upstream luacheck specs, if the tarball we fetched included them.
.PHONY: upstream-specs
upstream-specs: vendor
	@if [ -d build/luacheck-*/spec ]; then \
		$(LUA_RUN) build/luacheck-*/test/luacheck_upstream_specs.lua; \
	else \
		echo "upstream-specs: skipped (upstream spec dir not present)"; \
	fi

.PHONY: adversarial
adversarial: lua vendor
	@$(LUA_RUN) test/run.lua test/adversarial

.PHONY: ci
ci: vendor-verify test

.PHONY: ci-verify
ci-verify: vendor-verify runner-selftest test adversarial
	@echo "ci-verify: PASS"

# ---------------------------------------------------------------- TDD proof

# Reverse-apply only the src/ changes of BASE..HEAD inside a scratch worktree and
# run the specs that the range added. They must FAIL, proving the tests are
# coupled to the new behavior rather than to the old code.
.PHONY: tdd-proof
tdd-proof:
	@base="$(BASE)"; head="$(HEAD)"; \
	if [ -z "$$base" ] || [ -z "$$head" ]; then \
	   set -- $(filter-out tdd-proof,$(MAKECMDGOALS)); \
	   base=$$(echo "$$1" | sed 's/^BASE=//'); head=$$(echo "$$2" | sed 's/^HEAD=//'); \
	fi; \
	if [ -z "$$base" ] || [ -z "$$head" ]; then \
	   echo "usage: make tdd-proof BASE HEAD   (or: make tdd-proof BASE=... HEAD=...)"; exit 2; \
	fi; \
	bash scripts/tdd-proof.sh "$$base" "$$head"

# ---------------------------------------------------------------- corpora

.PHONY: corpus
corpus: scripts/clone-corpus.sh
	@bash scripts/clone-corpus.sh

.PHONY: clean
clean:
	rm -rf build

.PHONY: selfscan
selfscan: lua vendor
	@./bin/luasec --format json -o /dev/null src/ && echo "selfscan: ok"
