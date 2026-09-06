.PHONY: gen-vectors gen-delegated-mint-vectors
gen-vectors: ## Regenerate key-dependent vectors with a fresh issuer key (run once per rotation; never in CI)
	cd tools/gen && go run .

gen-delegated-mint-vectors: ## Regenerate delegated-mint signatures with fresh throwaway test keys (never in CI)
	cd tools/gen-delegated-mint && go run .
