module github.com/layervai/qurl-conformance/tools/verify-sdk

go 1.26.4

require (
	github.com/layervai/qurl-conformance v0.0.0 // local root via replace; legacy qv2 verifier needs no released assignment types
	github.com/layervai/qurl-go v0.0.0-20260628001303-02f1d1ba3092 // intentional: verifies the legacy exported qv2 package
	golang.org/x/crypto v0.54.0
)

require golang.org/x/sys v0.47.0 // indirect

replace github.com/layervai/qurl-conformance => ../..
