.PHONY: gen-vectors
gen-vectors: ## Regenerate key-dependent vectors with a fresh issuer key (run once per rotation; never in CI)
	cd tools/gen && go run .
