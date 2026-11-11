PREFIX ?= /usr/local
TARGET ?= x86_64-unknown-linux-musl
BIN := target/$(TARGET)/release/brainproxy

.PHONY: build static static-arm64 test check install install-arm64 clean

build:
	cargo build --release

# Fully static binary with no runtime dependencies. Needs: apt install musl-tools; rustup target add $(TARGET)
static:
	cargo build --release --target $(TARGET)
	@ls -la $(BIN)

# Static arm64 binary (Braintruder's Kali target). Needs: pip install ziglang; cargo install cargo-zigbuild;
# rustup target add aarch64-unknown-linux-musl
static-arm64:
	cargo zigbuild --release --target aarch64-unknown-linux-musl
	@ls -la target/aarch64-unknown-linux-musl/release/brainproxy

test:
	cargo test

check:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo test

install: static
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/brainproxy

install-arm64: static-arm64
	install -Dm755 target/aarch64-unknown-linux-musl/release/brainproxy $(DESTDIR)$(PREFIX)/bin/brainproxy

clean:
	cargo clean

# ---------------------------------------------------------------------------------------------
# Dev desktop packages: the GUI with its CLI sidecar, built to install beside a release.
# What a release and a dev build would share is renamed for dev (gui/src-tauri/tauri.dev.conf.json,
# merged over tauri.conf.json at build time): package and app brainproxy-dev, GUI binary
# brainproxy-gui-dev, CLI brainproxy-dev, identifier dev.brainproxy.gui-dev (its own app data),
# its own temp-engagement folder, an orange DEV icon, and a version naming the commit. The CLI
# home (CA, checks, rule data) is the release's. See docs/GUI.md, "Dev packages".

.PHONY: help dev-deb dev-macos dev-deb-check dev-macos-check dev-version
.NOTPARALLEL: dev-deb dev-macos

DIST ?= dist
DEV_NAME := brainproxy-dev
TAURI_DIR := gui/src-tauri
DEV_WORK := $(CURDIR)/target/dev-package
DEV_CONFIG := --config "$(CURDIR)/$(TAURI_DIR)/tauri.dev.conf.json" --config "$(DEV_WORK)/version.json"
HOST_ARCH = $(shell uname -m | sed 's/^arm64$$/aarch64/')
DEB_TARGET ?= $(HOST_ARCH)-unknown-linux-gnu
MAC_TARGET ?= $(HOST_ARCH)-apple-darwin
# The release asset's architecture for a Rust target: x86_64-unknown-linux-gnu -> x86_64.
asset_arch = $(subst aarch64,arm64,$(firstword $(subst -, ,$(1))))

# Recursive (=), so other targets never run git. <version>-dev.<commit time, UTC>.g<sha>[.dirty]:
# valid semver (Tauri) and a Debian version, in commit order; .dirty marks uncommitted changes
# and untracked files.
BASE_VERSION = $(shell sed -n 's/^version = "\([^"]*\)".*/\1/p' Cargo.toml | head -n1)
DEV_STAMP = $(shell TZ=UTC0 git log -1 --date=format-local:%Y%m%d%H%M%S --format=%cd)
DEV_VERSION = $(BASE_VERSION)-dev.$(DEV_STAMP).g$(shell git rev-parse --short=7 HEAD)$(shell [ -z "$$(git status --porcelain 2>/dev/null)" ] || echo .dirty)

help:
	@echo "CLI:"
	@echo "  make build           release build for this machine   -> target/release/brainproxy"
	@echo "  make static          static x86_64 musl binary         -> target/$(TARGET)/release/brainproxy"
	@echo "  make static-arm64    static arm64 musl binary (cargo-zigbuild)"
	@echo "  make install         static binary to $(PREFIX)/bin (set PREFIX, DESTDIR)"
	@echo "  make test | check    tests | fmt, clippy and tests"
	@echo "Dev desktop packages, to install beside a release (results and a .sha256 each in $(DIST)/):"
	@echo "  make dev-deb         Debian package brainproxy-dev, on Linux (DEB_TARGET=$(DEB_TARGET))"
	@echo "  make dev-macos       brainproxy-dev.app in a .dmg, on macOS (MAC_TARGET=$(MAC_TARGET));"
	@echo "                       ad-hoc signed only: not signed with a Developer ID, not notarised"
	@echo "  make dev-version     the version a dev package built now gets"

dev-version:
	@echo $(DEV_VERSION)

# $(1): the Rust target that must be installed.
define need_rust
command -v cargo > /dev/null || { echo "error: cargo not found: install Rust (https://rustup.rs)" >&2; exit 1; }; \
if command -v rustup > /dev/null; then rustup target list --installed | grep -qx '$(1)'; \
else [ -d "$$(rustc --print sysroot)/lib/rustlib/$(1)" ]; fi \
	|| { echo "error: the Rust target $(1) is not installed (rustup target add $(1))" >&2; exit 1; }
endef

define need_git
git rev-parse --verify -q HEAD > /dev/null \
	|| { echo "error: a dev package is versioned by its commit: build in a git checkout with at least one commit" >&2; exit 1; }
endef

define need_node
command -v node > /dev/null && command -v npm > /dev/null \
	|| { echo "error: the GUI needs Node.js 23.6+ and npm (https://nodejs.org)" >&2; exit 1; }; \
node -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 23 || (a == 23 && b >= 6) ? 0 : 1)' \
	|| { echo "error: Node.js $$(node --version) is too old: the GUI needs 23.6+" >&2; exit 1; }
endef

dev-deb-check:
	@[ "$$(uname -s)" = Linux ] || { echo "error: dev-deb builds on Linux (this is $$(uname -s))" >&2; exit 1; }
	@$(call need_git)
	@$(call need_rust,$(DEB_TARGET))
	@$(call need_node)
	@command -v pkg-config > /dev/null || { echo "error: pkg-config not found (sudo apt install pkg-config)" >&2; exit 1; }
	@missing=; for p in webkit2gtk-4.1 librsvg-2.0; do pkg-config --exists $$p || missing="$$missing $$p"; done; \
	[ -z "$$missing" ] || { echo "error: missing$$missing: sudo apt install libwebkit2gtk-4.1-dev librsvg2-dev" >&2; exit 1; }

dev-macos-check:
	@[ "$$(uname -s)" = Darwin ] || { echo "error: dev-macos runs on macOS only (this is $$(uname -s)): a .app and .dmg can't be built elsewhere" >&2; exit 1; }
	@command -v hdiutil > /dev/null && command -v codesign > /dev/null \
		|| { echo "error: hdiutil or codesign not found: install the Xcode command line tools (xcode-select --install)" >&2; exit 1; }
	@$(call need_git)
	@$(call need_rust,$(MAC_TARGET))
	@$(call need_node)

# npm ci when the lock file is newer than the last install (npm writes node_modules/.package-lock.json).
# A symlinked node_modules (shared with another checkout) is used as it is: npm ci would empty it.
gui/node_modules/.package-lock.json: gui/package-lock.json
	@if [ -L gui/node_modules ]; then echo "gui/node_modules is a symlink: using it as it is (no npm ci)"; \
	else echo "cd gui && npm ci"; cd gui && npm ci; fi

# Where Cargo puts a workspace's output ($(1): its Cargo.toml): target/, or $CARGO_TARGET_DIR or
# build.target-dir when set. The CLI workspace and the GUI's are separate.
target_dir = $(shell cargo metadata --format-version 1 --no-deps --manifest-path "$(1)" 2> /dev/null \
	| sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')

# The version, and both workspaces' output folders, once per build.
define dev_setup
$(eval DEV_V := $(DEV_VERSION))
$(eval CLI_OUT := $(call target_dir,Cargo.toml))
$(eval GUI_OUT := $(call target_dir,$(TAURI_DIR)/Cargo.toml))
@[ -n "$(CLI_OUT)" ] && [ -n "$(GUI_OUT)" ] || { echo "error: cargo metadata didn't say where the build output goes" >&2; exit 1; }
endef

# $(1): Rust target. Builds the CLI and puts it where Tauri's externalBin looks for brainproxy-dev.
define dev_sidecar
cargo build --release --target $(1) -p brainproxy
mkdir -p $(TAURI_DIR)/binaries "$(DEV_WORK)"
cp "$(CLI_OUT)/$(1)/release/brainproxy" $(TAURI_DIR)/binaries/$(DEV_NAME)-$(1)
chmod 755 $(TAURI_DIR)/binaries/$(DEV_NAME)-$(1)
endef

# $(1): bundle kind and extension (deb, dmg), $(2): Rust target, $(3): platform for the file name.
# Copies the one brainproxy-dev bundle Tauri made to $(DIST)/brainproxy-gui-<version>-<platform>.<ext>
# (named as CI names release assets) and writes its sha256 beside it.
define dev_collect
@set -- "$(GUI_OUT)/$(2)/release/bundle/$(1)/"$(DEV_NAME)_*.$(1); \
[ $$# -eq 1 ] && [ -f "$$1" ] || { echo "error: expected one $(DEV_NAME) .$(1) in bundle/$(1), found: $$*" >&2; exit 1; }; \
mkdir -p "$(DIST)" && name=brainproxy-gui-$(DEV_V)-$(3).$(1) && cp "$$1" "$(DIST)/$$name" && cd "$(DIST)" && \
{ if command -v sha256sum > /dev/null; then sha256sum "$$name"; else shasum -a 256 "$$name"; fi; } > "$$name.sha256" && \
echo "==> $(DIST)/$$name" && cat "$$name.sha256"
endef

dev-deb: dev-deb-check gui/node_modules/.package-lock.json
	$(dev_setup)
	@echo "==> $(DEV_NAME) $(DEV_V) for $(DEB_TARGET)"
	$(call dev_sidecar,$(DEB_TARGET))
	printf '{"version": "%s"}\n' '$(DEV_V)' > "$(DEV_WORK)/version.json"
	rm -f "$(GUI_OUT)/$(DEB_TARGET)/release/bundle/deb/"$(DEV_NAME)_*.deb
	cd gui && npx tauri build --target $(DEB_TARGET) --bundles deb $(DEV_CONFIG)
	$(call dev_collect,deb,$(DEB_TARGET),linux-$(call asset_arch,$(DEB_TARGET)))

# The app reports the full dev version, but Info.plist keeps Apple's numeric forms:
# CFBundleShortVersionString is Cargo.toml's version (Info.plist below, merged over Tauri's) and
# CFBundleVersion (bundleVersion) the commit time, one integer, so later dev builds count higher.
dev-macos: dev-macos-check gui/node_modules/.package-lock.json
	$(dev_setup)
	@echo "==> $(DEV_NAME) $(DEV_V) for $(MAC_TARGET) (ad-hoc signed, not notarised)"
	$(call dev_sidecar,$(MAC_TARGET))
	printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n\t<key>CFBundleShortVersionString</key>\n\t<string>%s</string>\n</dict>\n</plist>\n' '$(BASE_VERSION)' > "$(DEV_WORK)/Info.plist"
	printf '{"version": "%s", "bundle": {"macOS": {"bundleVersion": "%s", "infoPlist": "%s"}}}\n' '$(DEV_V)' '$(DEV_STAMP)' '$(DEV_WORK)/Info.plist' > "$(DEV_WORK)/version.json"
	rm -f "$(GUI_OUT)/$(MAC_TARGET)/release/bundle/dmg/"$(DEV_NAME)_*.dmg
	cd gui && npx tauri build --target $(MAC_TARGET) --bundles dmg $(DEV_CONFIG)
	$(call dev_collect,dmg,$(MAC_TARGET),macos-$(call asset_arch,$(MAC_TARGET)))
