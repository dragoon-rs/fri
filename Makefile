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

test:
	cargo test -- --nocapture
