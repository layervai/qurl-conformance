.PHONY: gen-vectors gen-delegated-mint-vectors gen-delegated-mint-vectors-rotate
gen-vectors: ## Regenerate key-dependent vectors with a fresh issuer key (run once per rotation; never in CI)
	cd tools/gen && go run .

gen-delegated-mint-vectors: ## Regenerate delegated-mint metadata while preserving committed test keys
	cd tools/gen-delegated-mint && go run .

gen-delegated-mint-vectors-rotate: ## Explicitly rotate all delegated-mint throwaway keys and signatures (never in CI)
	cd tools/gen-delegated-mint && go run . -rotate-keys
