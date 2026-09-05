# Delegated-mint capability issue v1

This artifact freezes the private request signature used when a trusted
Connector asks qurl-service to issue an opaque delegated-mint capability. It
does not expose capability claims to an SDK and it does not authorize a public
batch redemption.

The signature input is the ASCII domain `LV-QURL-CAPABILITY-ISSUE-V1`, one zero
byte, then nine fields in the listed order. Each field has a four-byte unsigned
big-endian byte length followed by its exact UTF-8 bytes. The body field is the
lowercase hexadecimal SHA-256 of the exact HTTP request body bytes. A consumer
must not parse and reserialize JSON before it computes this digest.

The signed headers are `Idempotency-Key`, `X-LayerV-Issuer-ID`,
`X-LayerV-Issuer-KID`, `X-LayerV-Timestamp`, and `X-LayerV-Nonce`.
`X-LayerV-Signature` carries the result. `X-LayerV-Nonce` is exactly 16 random
bytes in canonical unpadded base64url. `Idempotency-Key` is 1 to 128 bytes from
the listed unreserved ASCII alphabet. The golden uses the Connector form
`uci_<base64url SHA-256>`. The endpoint must bind the idempotency key and nonce
to the same authenticated issuer operation. The exact request body is limited
to 8,192 bytes before parsing or signature verification.

The signature is canonical ASN.1 DER ECDSA P-256 with low S, encoded as
canonical unpadded base64url. A verifier must reject padded or non-canonical
base64url, non-canonical DER, an out-of-range scalar, and a high-S malleability
twin. It must not normalize an untrusted signature.

The Connector selects neither the service-owned resource nor an arbitrary path
namespace. qurl-service loads both from issuer policy. The signed body carries
the exact issuer-produced object path and the authenticated caller's public
`audience_key_id`. Capability issuance is separate from later redemption with
that caller's normal qURL API credential.
