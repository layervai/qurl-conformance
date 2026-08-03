## Summary

<!-- Brief description of the changes -->

## Changes

-

## Test Plan

- [ ] `go test ./...` + `go vet ./...` pass; `gofmt` clean
- [ ] Vectors byte-identical across root/npm/python (`scripts/check-sync.sh`)
- [ ] Consumers verified against these vectors (qurl-go, layervai/nhp, qurl-typescript run this in their own CI; a protocol change lands here first and consumers adopt after release)
- [ ] npm + Python package smokes pass
- [ ] If any packet byte changed: `RELEASE_CHECKLIST.md` worked through (producer pins named truthfully, a consumer has cryptographically authenticated these exact bytes)

## Related Issues

<!-- Link any related issues: Fixes #123, Relates to #456 -->
