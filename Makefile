PREFIX ?= /usr/local
TARGET ?= x86_64-unknown-linux-musl
BIN := target/$(TARGET)/release/brainproxy

.PHONY: build static test check install clean

build:
	cargo build --release

# Fully static binary with no runtime dependencies. Needs: apt install musl-tools; rustup target add $(TARGET)
static:
	cargo build --release --target $(TARGET)
	@ls -la $(BIN)

test:
	cargo test

check:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo test

install: static
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/brainproxy

clean:
	cargo clean
