## Summary

<!-- Brief description of the changes -->

## Changes

-

## Test Plan

- [ ] `go test ./...` + `go vet ./...` pass; `gofmt` clean
- [ ] Vectors byte-identical across root/npm/python (`scripts/check-sync.sh`)
- [ ] Cross-language compat passes (`tools/verify-sdk`: `cd tools/verify-sdk && go test ./...`)
- [ ] npm + Python package smokes pass

## Related Issues

<!-- Link any related issues: Fixes #123, Relates to #456 -->
