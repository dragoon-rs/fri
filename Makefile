.PHONY: doc doc-open fmt fmt-check test

DOC_OPTIONS="--all-features --document-private-items --workspace"

doc-open:
	cargo doc "${DOC_OPTIONS}" --open

doc:
	cargo doc "${DOC_OPTIONS}"

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

.PHONY: check
check:
	cargo check --workspace --all-targets
	cargo check --workspace --all-targets --all-features

.PHONY: clippy
clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace -- --nocapture
