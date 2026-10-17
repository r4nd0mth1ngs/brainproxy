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
