module github.com/layervai/qurl-conformance/tools/verify-assignment

go 1.26.5

require (
	github.com/layervai/qurl-conformance v0.2.0 // qurl-go producer imports the v0.2 assignment contract; replaced locally
	github.com/layervai/qurl-go v0.0.0-20260716040040-8a6964295703
)

require (
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace github.com/layervai/qurl-conformance => ../..
