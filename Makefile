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
	@echo "  make ci-verify  full gate (vendor + upstream specs + our specs + adversarial + precision)"
	@echo "  make tdd-proof BASE HEAD   prove new tests fail without the new src"
	@echo "  make precision re-measure corpus/ and fail on any difference from the frozen numbers"
	@echo "  make corpus     clone firmware Lua corpora into corpus/ (network)"
	@echo "  make lua55-check  compile every src/ file under Lua 5.5 (skips without one)"
	@echo "  make selfscan   scan src/ with luasec itself"
	@echo "  make self-lint  lint src/ with the vendored luacheck"
	@echo "  make self-lint-bless   re-take test/self-lint-baseline.txt after a deliberate change"
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
	@mkdir -p test/adversarial
	@if [ -z "$$(find test/adversarial -name '*_spec.lua' -type f 2>/dev/null | head -1)" ]; then \
	   echo "adversarial: FAIL - test/adversarial has no specs; the gate would pass vacuously"; exit 1; \
	fi
	@$(LUA_RUN) test/run.lua test/adversarial

.PHONY: ci
ci: vendor-verify test

# Re-take the measurement docs/precision.md describes and hold it against the
# frozen copy in scripts/precision-golden.lua. The spec is the other half of this
# gate and can only tell that the document agrees with the frozen file, which is
# a check that passes just as happily when a rule regression has moved both.
# This is the half that runs the analyzer, so it is the half that notices.
#
# corpus/ is absent on a fresh checkout: `make corpus` clones it and that needs
# the network, so the skip below is the normal case in CI and it says so in three
# lines rather than going quiet. Exiting non-zero there would be a gate that is
# red on every fresh runner, and a gate like that gets deleted rather than
# fixed; so it exits 0, says SKIPPED, and says that the measurement was not
# taken. PRECISION_REQUIRE_CORPUS=1 makes that skip fatal for a job that has the
# corpora and must not proceed without a measurement.
#
# The corpus is verified before the analyzer runs, not compared after. The two
# frozen file counts do catch a corpus that shrank, but they report it as
# arithmetic - "corpus holds N .lua files, the frozen measurement says M" - which
# names no checkout, and they cannot catch a pinned entry moved to another commit
# at all: same number of files, different code in them. scripts/clone-corpus.sh
# --verify names the entry and exits non-zero, so the run below is not taken over
# a tree the frozen numbers do not describe. test/spec/corpus_spec.lua fails if
# the verify is removed from here or from behind the analyzer.
PRECISION_REPORT ?= build/precision-report.json
PRECISION_REQUIRE_CORPUS ?= 0

.PHONY: precision
precision: lua vendor
	@if [ ! -d corpus ]; then \
	   echo "precision: SKIPPED - corpus/ is absent, so luasec was NOT run over the firmware corpora"; \
	   echo "precision: SKIPPED - the measurement was NOT taken. This is not a pass: it is not evidence"; \
	   echo "precision: SKIPPED - that luasec still finds what docs/precision.md claims. Run: make corpus && make precision"; \
	   if [ "$(PRECISION_REQUIRE_CORPUS)" = "1" ]; then \
	     echo "precision: FAIL - PRECISION_REQUIRE_CORPUS=1 and corpus/ is absent"; exit 1; \
	   fi; \
	   exit 0; \
	fi; \
	echo ">> verifying corpus/ against what scripts/clone-corpus.sh declares"; \
	bash scripts/clone-corpus.sh --verify corpus \
	  || { echo "precision: FAIL - corpus/ is not what clone-corpus.sh declares it to be,"; \
	       echo "precision: FAIL - so the run below would describe a different corpus than"; \
	       echo "precision: FAIL - the frozen numbers, and it is not a measurement of either"; \
	       exit 1; }; \
	echo ">> luasec over corpus/ (this is the measurement)"; \
	./bin/luasec --std +openwrt+luci+luajit --format json -o $(PRECISION_REPORT) corpus; \
	status=$$?; \
	if [ $$status -gt 1 ]; then \
	   echo "precision: FAIL - luasec exited $$status, which is an error rather than findings,"; \
	   echo "precision: FAIL - so $(PRECISION_REPORT) is not a measurement and will not be compared"; \
	   exit 1; \
	fi; \
	if [ $$status -eq 1 ]; then \
	   echo ">> luasec exited 1: findings at or above the threshold, and files it could not"; \
	   echo ">> parse. Both are expected over this corpus, and the report is written either way."; \
	fi; \
	$(LUA_RUN) scripts/precision-check.lua --corpus corpus --report $(PRECISION_REPORT)

.PHONY: ci-verify
ci-verify: vendor-verify runner-selftest self-lint test adversarial precision
	@echo "ci-verify: PASS"

# Accept the two positional shas of `make tdd-proof BASE HEAD` as goals. Make
# would otherwise refuse to run the recipe because those goals do not exist.
# A goal that is not a git sha is still an error, so typos are not swallowed.
%:
	@case "$$@" in \
	  [0-9a-f]*) : ;; \
	  *) echo "unknown target: $$@ (expected a git sha, e.g. make tdd-proof 83e9c9a 7b576bb)"; exit 2 ;; \
	esac

# ---------------------------------------------------------------- TDD proof

# Reverse-apply only the src/ changes of BASE..HEAD inside a scratch worktree and
# run the specs that the range added. They must FAIL, proving the tests are
# coupled to the new behavior rather than to the old code.

# The recipe above reads its operands out of MAKECMDGOALS, but make still
# considers every bare word on the command line a goal to build. Give the shas an
# empty recipe so make does not look for a file named after the commit and exit 2
# after the proof has already printed its verdict. Guarded on tdd-proof actually
# being a goal, so `make test` does not acquire a rule for the word "test".
ifneq ($(filter tdd-proof,$(MAKECMDGOALS)),)
$(filter-out tdd-proof,$(MAKECMDGOALS)):
	@:
endif

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

# Clone what is missing, then verify the whole tree against the list the script
# itself declares. The verify is not decoration: a clone that fails part-way
# leaves a corpus that still scans, and a pinned checkout that was moved leaves
# one whose file counts are unchanged and whose code is not. Both are what the
# frozen numbers would then be compared against. `make precision` runs the same
# --verify before it measures, so a corpus that drifted is caught whether or not
# `make corpus` was the thing that left it that way.
.PHONY: corpus
corpus: scripts/clone-corpus.sh
	@bash scripts/clone-corpus.sh

.PHONY: clean
clean:
	rm -rf build

# Every other check runs on the Lua 5.4 built above; Homebrew installs 5.5, which
# refuses code 5.4 accepts. Skips with a notice without a 5.5, fails in CI.
.PHONY: lua55-check
lua55-check:
	@sh scripts/check-lua55.sh

.PHONY: selfscan
selfscan: lua vendor
	@./bin/luasec --format json -o /dev/null src/ && echo "selfscan: ok"

# Lint src/ with the luacheck that already ships in vendor/. `make selfscan`
# above runs luasec over its own source and cannot see a global assignment -
# luasec has no rule for that class - so a function that lost its `local`
# compiled, worked and shipped as a global through a fully green build (#277).
#
# The comparison is against a frozen list rather than against zero, because src/
# does not lint clean today: it carries 111 and 113 of its own. Anything not in
# that list fails the run, so this is a ratchet and not a rubber stamp. The two
# halves are checked independently as well - test/spec/module_globals_spec.lua
# asserts the same thing without reading a lint's configuration, and the lint
# reads code the spec does not load (src/luasec/validate/child.lua is a
# concatenated sandbox script, not a module).
SELF_LINT_BASELINE ?= test/self-lint-baseline.txt
SELF_LINT_DIR      ?= src

.PHONY: self-lint
self-lint: lua vendor
	@$(LUA_RUN) test/self-lint.lua --baseline $(SELF_LINT_BASELINE) $(SELF_LINT_DIR)

# Deliberate only. Run it after you have decided the new warnings are ones this
# tree should carry, and read the lines it prints: it will happily accept the
# very global this gate exists to refuse.
.PHONY: self-lint-bless
self-lint-bless: lua vendor
	@$(LUA_RUN) test/self-lint.lua --bless --baseline $(SELF_LINT_BASELINE) $(SELF_LINT_DIR)
