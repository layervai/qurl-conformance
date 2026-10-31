# Relay knock golden packets

Schema v1 carries a deterministic `knock` and a frozen, independently generated
`ack`. Their counters differ. They remain unchanged decoder fixtures; v1 does
not claim that this ACK replies to this knock.

Schema v2 adds `matched_ack`. The reference responder decrypts the committed
knock and seals this new ACK through its parsed-request response path. The
request context supplies the reply counter. A client must decrypt it, recover
ACK type and body, and require its counter to equal `knock.counter`.

The new reply uses the same synthetic peers and response body as the existing
fixtures. It was generated once with a random server ephemeral and is frozen;
clients cannot reproduce its bytes. No old packet, key or signature was changed.

`knock.counter` is a canonical decimal uint64 string. `matched_ack.counter_hex`
is a canonical lowercase uint64 hex string with no prefix or padding. The
24-byte common header stores the counter as big-endian bytes 16 through 23.
Both packet headers and both metadata values must agree. Go's loader checks
these structural facts, required fields, peers and supported versions 1/2; it
does not replace the consumers' real handshake decryption tests.

Consumers can keep v1 compatibility, but must require and execute the matched
case for v2. Reject unknown schema versions. Preserve the original unmatched ACK
as a negative control for request/reply correlation.

The registration corpus already contains a matched `reg_emailed` to
`rak_success`/`rak_error` pair. Execute both families to cover KNK→ACK and REG→RAK
counter echo. A release waits for reference-producer, Go and independent
TypeScript/WebCrypto checks against the exact committed packet bytes.
