.PHONY: gen-vectors
gen-vectors: ## Regenerate key-dependent vectors with fixed public keys (run once per rotation; never in CI)
	cd tools/gen && go run .
