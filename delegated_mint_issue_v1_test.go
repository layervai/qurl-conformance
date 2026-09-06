package conformance

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestEmbeddedDelegatedMintIssueV1LoadsAndVerifies(t *testing.T) {
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatalf("DelegatedMintIssueV1(): %v", err)
	}
	if file.Artifact != DelegatedMintIssueV1ArtifactID || file.SchemaVersion != DelegatedMintIssueV1SchemaVersion {
		t.Fatalf("identity = %q/v%d", file.Artifact, file.SchemaVersion)
	}
	for _, golden := range []DelegatedMintIssueV1Golden{
		file.Golden,
		file.RetryGolden,
		file.RefreshGolden,
		file.WrongEndpointSigned,
		file.NonceReuseSigned,
		file.AuthorityConflictSigned,
	} {
		canonical, err := DelegatedMintIssueV1CanonicalBytes(golden)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(canonical); got == 0 {
			t.Fatal("canonical signature input is empty")
		}
	}
	if len(file.Golden.Nonce) != 22 || len(file.RetryGolden.Nonce) != 22 || len(file.RefreshGolden.Nonce) != 22 ||
		file.Contract.IdempotencyKeyPrefix != DelegatedMintIssueV1IdempotencyKeyPrefix ||
		!strings.HasPrefix(file.Golden.IdempotencyKey, file.Contract.IdempotencyKeyPrefix) || !strings.HasPrefix(file.Golden.BodyUTF8, `{"upload_handle":"upl_`) {
		t.Fatal("golden Connector identifier shapes drifted")
	}
	if file.Contract.TimestampMaxSkewSeconds != 300 || file.Contract.NonceReplayRetentionSeconds != 900 ||
		file.Contract.NonceReplayRetentionSeconds <= 2*file.Contract.TimestampMaxSkewSeconds ||
		file.Contract.AuthorityBindingRule != DelegatedMintIssueV1AuthorityBindingRule ||
		file.Contract.ExpiryEncoding != DelegatedMintIssueV1ExpiryEncoding ||
		file.Contract.SuccessReconciliationRule != "authority_expiry_equals_immutable_operation_authority_capability_expiry_is_canonical_and_not_after_authority_expired_capability_advances_generation" ||
		file.Contract.ErrorContentType != DelegatedMintIssueV1ErrorContentType ||
		file.Contract.ErrorEnvelope != "rfc7807_error_object_plus_meta_request_id_no_unknown_fields" ||
		file.Contract.BodySemanticValidationRule != "receiver_strictly_decodes_and_validates_every_body_authority_field_before_state_access_service_policy_owns_runtime_ceilings" ||
		!slices.Equal(file.Contract.BodyAuthorityFields, delegatedMintIssueV1BodyAuthorityFields) ||
		file.Contract.ExternalOperationCommitRule != "uncommitted_external_operation_may_advance_internal_issue_generation_within_same_authority_committed_external_response_replays_byte_exact_new_outward_capability_requires_new_signed_external_request" ||
		file.Contract.ExpiryAuthorityRule != "caller_supplies_signed_values_service_requires_capability_timestamp_plus_900_and_initial_authority_at_most_timestamp_plus_86400_refresh_preserves_authority" ||
		file.Contract.ExactReplayFreshnessRule != "verify_shape_signature_then_operation_lookup_before_freshness_exact_accepted_envelope_returns_original_same_operation_authority_fresh_envelope_reconciles_changed_authority_conflicts_stale_nonexact_rejects_without_mutation" ||
		file.Contract.TransportReplayRule != "exact_accepted_envelope_may_bypass_freshness_same_operation_authority_different_envelope_requires_fresh_timestamp_and_nonce_binding_issuer_kid_may_rotate" ||
		file.Contract.StaleOperationMissRule != "authenticated_strongly_consistent_absent_stale_operation_returns_no_mutation_connector_retries_fresh_same_generation" ||
		file.Contract.StaleOperationMissStatus != DelegatedMintIssueV1StaleMissStatus ||
		file.Contract.StaleOperationMissCode != DelegatedMintIssueV1StaleMissCode ||
		file.Contract.IssuerKeyRetentionRule != "accepted_kid_verifier_retained_until_operation_authority_expires" ||
		!slices.Equal(file.Contract.OperationIdentityFields, []string{"issuer_id", "upload_handle", "issue_generation", "idempotency_key"}) ||
		!slices.Equal(file.Contract.AuthorityFingerprintFields, []string{"upload_request_digest", "content_sha256", "byte_size", "media_type", "display_filename", "audience_key_id", "target_path", "max_batch_size", "max_link_ttl_seconds", "authority_expires_at", "service_owned_issuer_policy_fingerprint"}) ||
		!slices.Equal(file.Contract.EnvelopeFingerprintFields, []string{"method", "authority", "route", "issuer_id", "kid", "idempotency_key", "timestamp_unix_decimal", "nonce", "exact_body_sha256", "signature_der_b64url"}) ||
		!slices.Equal(file.Contract.RejectClasses, []string{"authority", "body_size", "idempotency_key", "nonce", "signature_encoding", "signature_malleability", "signature_scalar", "signature_mismatch"}) ||
		!slices.Equal(file.Contract.StateOutcomes, []string{"issue_new", "return_durable_result", "reject"}) ||
		!slices.Equal(file.Contract.StateMutations, []string{"store_operation_and_bind_nonce", "bind_nonce_to_existing_operation", "none"}) ||
		!slices.Equal(file.Contract.RetryAfterModes, []string{"absent", "exact_seconds", "positive_integer_seconds"}) {
		t.Fatalf("freshness/replay/expiry authority contract drifted: %+v", file.Contract)
	}
	if len(file.RejectCases) != 9 {
		t.Fatalf("reject case count = %d, want 9", len(file.RejectCases))
	}
	if len(file.StateCases) != 9 {
		t.Fatalf("state case count = %d, want 9", len(file.StateCases))
	}
	if len(file.ResponseCases) != 8 {
		t.Fatalf("response case count = %d, want 8", len(file.ResponseCases))
	}
	var body struct {
		UploadHandle        string `json:"upload_handle"`
		AudienceKeyID       string `json:"audience_key_id"`
		TargetPath          string `json:"target_path"`
		CapabilityExpiresAt string `json:"capability_expires_at"`
		AuthorityExpiresAt  string `json:"authority_expires_at"`
	}
	if err := json.Unmarshal([]byte(file.Golden.BodyUTF8), &body); err != nil {
		t.Fatalf("decode golden body: %v", err)
	}
	if body.UploadHandle != "upl_VGWeFxH8fk_znKtylEoZVkRb8AXlTbIS03Yj5ssVO70" ||
		body.AudienceKeyID != "key_A1b2C3d4E5f6" || body.TargetPath != "/files/"+body.UploadHandle ||
		body.CapabilityExpiresAt == body.AuthorityExpiresAt {
		t.Fatalf("golden body binding drifted: %+v", body)
	}
	initialAuthority, err := time.Parse(time.RFC3339, body.AuthorityExpiresAt)
	if err != nil || initialAuthority.Sub(time.Unix(file.Golden.TimestampUnix, 0)) != 24*time.Hour {
		t.Fatalf("golden authority window drifted: %v", err)
	}
}

func TestDelegatedMintIssueV1StaleMissRetryKeepsOperationAuthority(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	if file.Golden.BodySHA256 == file.RetryGolden.BodySHA256 ||
		file.Golden.CanonicalHex == file.RetryGolden.CanonicalHex {
		t.Fatal("fresh stale-miss retry reused its old transport envelope")
	}
	if file.Golden.KID == file.RetryGolden.KID ||
		file.Golden.PublicKeyDERB64URL == file.RetryGolden.PublicKeyDERB64URL {
		t.Fatal("fresh stale-miss retry did not exercise issuer-key rotation")
	}
	if err := validateDelegatedMintIssueV1StaleRetry(file.Golden, file.RetryGolden); err != nil {
		t.Fatalf("valid fresh same-generation retry rejected: %v", err)
	}
}

func TestDelegatedMintIssueV1StaleMissRetryCannotChangeAuthority(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DelegatedMintIssueV1Golden){
		"idempotency": func(golden *DelegatedMintIssueV1Golden) { golden.IdempotencyKey += "x" },
		"nonce reuse": func(golden *DelegatedMintIssueV1Golden) { golden.Nonce = file.Golden.Nonce },
		"not stale":   func(golden *DelegatedMintIssueV1Golden) { golden.TimestampUnix = file.Golden.TimestampUnix + 300 },
		"generation": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"issue_generation":1`, `"issue_generation":2`, 1)
		},
		"content": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"byte_size":1048576`, `"byte_size":1048577`, 1)
		},
		"authority expiry": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"authority_expires_at":"2026-09-06T23:15:00Z"`, `"authority_expires_at":"2026-09-06T23:16:00Z"`, 1)
		},
		"capability unchanged": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"capability_expires_at":"2026-09-05T23:40:00Z"`, `"capability_expires_at":"2026-09-05T23:30:00Z"`, 1)
		},
		"capability past authority": func(golden *DelegatedMintIssueV1Golden) {
			golden.TimestampUnix = 1788735900
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"capability_expires_at":"2026-09-05T23:40:00Z"`, `"capability_expires_at":"2026-09-06T23:20:00Z"`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			retry := file.RetryGolden
			mutate(&retry)
			if err := validateDelegatedMintIssueV1StaleRetry(file.Golden, retry); err == nil {
				t.Fatal("invalid stale-miss retry unexpectedly accepted")
			}
		})
	}
}

func TestDelegatedMintIssueV1PublishedRejectsFailClosed(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	wantClasses := map[string]string{
		"reject_padded_signature":             "signature_encoding",
		"reject_noncanonical_signature_der":   "signature_encoding",
		"reject_high_s_signature":             "signature_malleability",
		"reject_zero_r_signature":             "signature_scalar",
		"reject_oversize_body":                "body_size",
		"reject_bad_idempotency_key":          "idempotency_key",
		"reject_uppercase_authority":          "authority",
		"reject_short_nonce":                  "nonce",
		"reject_changed_body_stale_signature": "signature_mismatch",
	}
	for _, reject := range file.RejectCases {
		t.Run(reject.Name, func(t *testing.T) {
			if reject.RejectClass != wantClasses[reject.Name] {
				t.Fatalf("reject class = %q, want %q", reject.RejectClass, wantClasses[reject.Name])
			}
			mutated, err := delegatedMintIssueV1ApplyReject(file.Golden, reject)
			if err != nil {
				t.Fatal(err)
			}
			if got := delegatedMintIssueV1RejectClass(mutated); got != reject.RejectClass {
				t.Fatalf("published reject classified as %q, want %q", got, reject.RejectClass)
			}
			wantStatus, wantCode := 403, DelegatedMintIssueV1AuthFailureCode
			if reject.RejectClass == "body_size" {
				wantStatus, wantCode = 413, "payload_too_large"
			}
			if reject.Status != wantStatus || reject.ErrorCode != wantCode {
				t.Fatalf("published reject response = %d/%q, want %d/%q", reject.Status, reject.ErrorCode, wantStatus, wantCode)
			}
		})
	}
}

func TestDelegatedMintIssueV1NonceReuseStateIsReachable(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	earliestInitialAcceptance := file.Golden.TimestampUnix - int64(file.Contract.TimestampMaxSkewSeconds)
	if file.NonceReuseSigned.TimestampUnix-earliestInitialAcceptance >= int64(file.Contract.NonceReplayRetentionSeconds) {
		t.Fatal("nonce-reuse request can occur at or after the original nonce retention boundary")
	}
	var state DelegatedMintIssueV1StateCase
	for _, candidate := range file.StateCases {
		if candidate.Name == "reused_nonce_across_operation" {
			state = candidate
			break
		}
	}
	skew := int64(file.Contract.TimestampMaxSkewSeconds)
	freshnessDelta := state.NowUnix - file.NonceReuseSigned.TimestampUnix
	if state.Name != "reused_nonce_across_operation" || state.NowUnix != file.NonceReuseSigned.TimestampUnix ||
		state.NowUnix-earliestInitialAcceptance >= int64(file.Contract.NonceReplayRetentionSeconds) ||
		freshnessDelta < -skew || freshnessDelta > skew {
		t.Fatalf("nonce-reuse state is not reachable: %+v", state)
	}
}

func TestDelegatedMintIssueV1StateIncludesGeneration2Refresh(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range file.StateCases {
		if state.Name == "generation_2_refresh" {
			if state.Input != "refresh_golden" || state.Outcome != "issue_new" || state.Status != 200 ||
				state.Mutation != "store_operation_and_bind_nonce" || !state.StrongOperationLookup {
				t.Fatalf("generation-2 refresh state drifted: %+v", state)
			}
			return
		}
	}
	t.Fatal("generation-2 refresh state is absent")
}

func TestDelegatedMintIssueV1KIDMapsToOnePublicKey(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	keys := make(map[string]string)
	for _, golden := range []DelegatedMintIssueV1Golden{
		file.Golden, file.RetryGolden, file.RefreshGolden, file.WrongEndpointSigned,
		file.NonceReuseSigned, file.AuthorityConflictSigned,
	} {
		if prior, ok := keys[golden.KID]; ok && prior != golden.PublicKeyDERB64URL {
			t.Fatalf("kid %q maps to multiple public keys", golden.KID)
		}
		keys[golden.KID] = golden.PublicKeyDERB64URL
	}
}

func TestDelegatedMintIssueV1ResponseRetryAfterRules(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, response := range file.ResponseCases {
		switch response.Name {
		case "rate_limit_exceeded":
			if response.RetryAfter.Mode != DelegatedMintIssueV1RetryAfterPositiveSeconds || response.RetryAfter.Seconds != 0 {
				t.Fatalf("rate-limit Retry-After = %+v", response.RetryAfter)
			}
		case "mutation_outcome_unknown":
			if response.RetryAfter.Mode != DelegatedMintIssueV1RetryAfterExactSeconds || response.RetryAfter.Seconds != 1 {
				t.Fatalf("mutation-unknown Retry-After = %+v", response.RetryAfter)
			}
		default:
			if response.RetryAfter.Mode != DelegatedMintIssueV1RetryAfterAbsent || response.RetryAfter.Seconds != 0 {
				t.Fatalf("%s Retry-After = %+v", response.Name, response.RetryAfter)
			}
		}
	}
}

func TestOpenDelegatedMintIssueV1Artifact(t *testing.T) {
	want := DelegatedMintIssueV1Vectors()
	for _, name := range []string{"delegated_mint_issue_v1_vectors.json", "vectors/delegated_mint_issue_v1_vectors.json"} {
		got, err := Open(name)
		if err != nil {
			t.Fatalf("Open(%q): %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Open(%q) does not match embedded vectors", name)
		}
	}
}

func TestParseDelegatedMintIssueV1FileFailsClosed(t *testing.T) {
	raw := DelegatedMintIssueV1Vectors()
	for name, invalid := range map[string][]byte{
		"duplicate key":  bytes.Replace(raw, []byte(`"artifact":`), []byte(`"artifact":"duplicate","artifact":`), 1),
		"unknown field":  bytes.Replace(raw, []byte("{"), []byte(`{"future":true,`), 1),
		"trailing value": append(append([]byte(nil), raw...), []byte("{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDelegatedMintIssueV1File(invalid); err == nil {
				t.Fatal("invalid artifact unexpectedly accepted")
			}
		})
	}

	mutate := func(t *testing.T, change func(*DelegatedMintIssueV1File)) []byte {
		t.Helper()
		var file DelegatedMintIssueV1File
		if err := json.Unmarshal(raw, &file); err != nil {
			t.Fatal(err)
		}
		change(&file)
		body, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, test := range []struct {
		name   string
		change func(*DelegatedMintIssueV1File)
	}{
		{name: "contract", change: func(file *DelegatedMintIssueV1File) { file.Contract.NonceDecodedBytes++ }},
		{name: "body", change: func(file *DelegatedMintIssueV1File) { file.Golden.BodyUTF8 += " " }},
		{name: "refresh body", change: func(file *DelegatedMintIssueV1File) { file.RefreshGolden.BodyUTF8 += " " }},
		{name: "canonical", change: func(file *DelegatedMintIssueV1File) {
			file.Golden.CanonicalHex = strings.Repeat("0", len(file.Golden.CanonicalHex))
		}},
		{name: "signing digest", change: func(file *DelegatedMintIssueV1File) {
			file.Golden.SigningDigestHex = strings.Repeat("0", len(file.Golden.SigningDigestHex))
		}},
		{name: "timestamp", change: func(file *DelegatedMintIssueV1File) { file.Golden.TimestampUnix = 0 }},
		{name: "signature", change: func(file *DelegatedMintIssueV1File) {
			replacement := "A"
			if strings.HasSuffix(file.Golden.SignatureDERB64URL, replacement) {
				replacement = "B"
			}
			file.Golden.SignatureDERB64URL = file.Golden.SignatureDERB64URL[:len(file.Golden.SignatureDERB64URL)-1] + replacement
		}},
		{name: "padded signature", change: func(file *DelegatedMintIssueV1File) { file.Golden.SignatureDERB64URL += "=" }},
		{name: "oversized signature", change: func(file *DelegatedMintIssueV1File) {
			file.Golden.SignatureDERB64URL = strings.Repeat("A", base64.RawURLEncoding.EncodedLen(DelegatedMintIssueV1SignatureDERMaxBytes)+1)
		}},
		{name: "high-S signature", change: func(file *DelegatedMintIssueV1File) {
			der, err := base64.RawURLEncoding.Strict().DecodeString(file.Golden.SignatureDERB64URL)
			if err != nil {
				t.Fatal(err)
			}
			var signature struct{ R, S *big.Int }
			if rest, err := asn1.Unmarshal(der, &signature); err != nil || len(rest) != 0 {
				t.Fatalf("parse signature: rest=%x err=%v", rest, err)
			}
			signature.S = new(big.Int).Sub(elliptic.P256().Params().N, signature.S)
			highDER, err := asn1.Marshal(signature)
			if err != nil {
				t.Fatal(err)
			}
			file.Golden.SignatureDERB64URL = base64.RawURLEncoding.EncodeToString(highDER)
		}},
		{name: "nonce", change: func(file *DelegatedMintIssueV1File) { file.Golden.Nonce = "AA" }},
		{name: "idempotency", change: func(file *DelegatedMintIssueV1File) { file.Golden.IdempotencyKey = "bad key" }},
		{name: "signed alternate endpoint", change: func(file *DelegatedMintIssueV1File) {
			file.WrongEndpointSigned.SignatureDERB64URL = file.Golden.SignatureDERB64URL
		}},
		{name: "signed authority conflict", change: func(file *DelegatedMintIssueV1File) {
			file.AuthorityConflictSigned.SignatureDERB64URL = file.Golden.SignatureDERB64URL
		}},
		{name: "oversized repeat recipe", change: func(file *DelegatedMintIssueV1File) {
			for i := range file.RejectCases {
				if file.RejectCases[i].Operation == "ascii_repeat" {
					file.RejectCases[i].Repeat = DelegatedMintIssueV1BodyMaxBytes + 2
					return
				}
			}
			t.Fatal("artifact has no ascii_repeat reject case")
		}},
		{name: "state case", change: func(file *DelegatedMintIssueV1File) { file.StateCases[0].Outcome = "future" }},
		{name: "response case", change: func(file *DelegatedMintIssueV1File) { file.ResponseCases[0].Status++ }},
		{name: "retry mode", change: func(file *DelegatedMintIssueV1File) { file.ResponseCases[0].RetryAfter.Mode = "future" }},
		{name: "reject response", change: func(file *DelegatedMintIssueV1File) { file.RejectCases[0].Status = 400 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseDelegatedMintIssueV1File(mutate(t, test.change)); err == nil {
				t.Fatal("mutated artifact unexpectedly accepted")
			}
		})
	}
}

func TestDelegatedMintIssueV1RelationsRejectKeyRotationDrift(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*DelegatedMintIssueV1File)
	}{
		{name: "rotated kid", change: func(changed *DelegatedMintIssueV1File) {
			changed.RetryGolden.KID = changed.Golden.KID
		}},
		{name: "rotated public key", change: func(changed *DelegatedMintIssueV1File) {
			changed.RetryGolden.PublicKeyDERB64URL = changed.Golden.PublicKeyDERB64URL
		}},
		{name: "nonce reuse key", change: func(changed *DelegatedMintIssueV1File) {
			changed.NonceReuseSigned.PublicKeyDERB64URL = changed.Golden.PublicKeyDERB64URL
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			changed := *file
			test.change(&changed)
			if err := validateDelegatedMintIssueV1Relations(&changed); err == nil {
				t.Fatal("rotation drift was accepted")
			}
		})
	}
}

func TestDelegatedMintIssueV1IdempotencyAndAuthority(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	for generation, want := range map[int]string{
		1: file.Golden.IdempotencyKey,
		2: file.RefreshGolden.IdempotencyKey,
	} {
		got, err := DelegatedMintIssueV1IdempotencyKey("fileviewer-sandbox", "upl_VGWeFxH8fk_znKtylEoZVkRb8AXlTbIS03Yj5ssVO70", generation)
		if err != nil || got != want {
			t.Fatalf("generation %d idempotency = %q, %v; want %q", generation, got, err, want)
		}
	}
	for _, authority := range []string{
		"localhost", "127.0.0.1", "[::1]", "api.layerv.ai:443", "api..layerv.ai",
		"api.layerv.ai.", "-api.layerv.ai", "api-.layerv.ai", "api_internal.layerv.ai",
		"API.layerv.ai", "api.layerv.ai\n", "é.layerv.ai",
		"user@api.layerv.ai", "api.layerv.ai/path", "api.layerv.ai?query",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62),
	} {
		if validDelegatedMintIssueV1Authority(authority) {
			t.Errorf("authority %q unexpectedly accepted", authority)
		}
	}
	for _, authority := range []string{
		"a.b", "api-internal.layerv.ai", "0.a",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61),
	} {
		if !validDelegatedMintIssueV1Authority(authority) {
			t.Errorf("authority %q unexpectedly rejected", authority)
		}
	}
}

func TestDelegatedMintIssueV1RenewalCannotWidenAuthority(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DelegatedMintIssueV1Golden){
		"method":      func(golden *DelegatedMintIssueV1Golden) { golden.Method = "PUT" },
		"authority":   func(golden *DelegatedMintIssueV1Golden) { golden.Authority = "other.internal.sandbox.layerv.ai" },
		"route":       func(golden *DelegatedMintIssueV1Golden) { golden.Route += "/other" },
		"issuer":      func(golden *DelegatedMintIssueV1Golden) { golden.IssuerID = "watermark-sandbox" },
		"nonce reuse": func(golden *DelegatedMintIssueV1Golden) { golden.Nonce = file.Golden.Nonce },
		"generation": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"issue_generation":2`, `"issue_generation":3`, 1)
		},
		"idempotency preimage": func(golden *DelegatedMintIssueV1Golden) {
			golden.IdempotencyPreimageHex += "00"
		},
		"batch limit": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"max_batch_size":100`, `"max_batch_size":101`, 1)
		},
		"link TTL limit": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"max_link_ttl_seconds":86400`, `"max_link_ttl_seconds":86401`, 1)
		},
		"audience": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"audience_key_id":"key_A1b2C3d4E5f6"`, `"audience_key_id":"key_Z9y8X7w6V5u4"`, 1)
		},
		"authority expiry": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"authority_expires_at":"2026-09-06T23:15:00Z"`, `"authority_expires_at":"2026-09-07T23:15:00Z"`, 1)
		},
		"capability past authority": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"capability_expires_at":"2026-09-06T00:00:00Z"`, `"capability_expires_at":"2026-09-07T00:00:00Z"`, 1)
		},
		"offset expiry": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"capability_expires_at":"2026-09-06T00:00:00Z"`, `"capability_expires_at":"2026-09-06T00:00:00+00:00"`, 1)
		},
		"fractional expiry": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"capability_expires_at":"2026-09-06T00:00:00Z"`, `"capability_expires_at":"2026-09-06T00:00:00.000Z"`, 1)
		},
		"lowercase-z expiry": func(golden *DelegatedMintIssueV1Golden) {
			golden.BodyUTF8 = strings.Replace(golden.BodyUTF8, `"capability_expires_at":"2026-09-06T00:00:00Z"`, `"capability_expires_at":"2026-09-06T00:00:00z"`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			refresh := file.RefreshGolden
			mutate(&refresh)
			if err := validateDelegatedMintIssueV1Renewal(file.Golden, refresh); err == nil {
				t.Fatal("widened refresh unexpectedly accepted")
			}
		})
	}
}

func TestDelegatedMintIssueV1RefreshCanRotateIssuerKey(t *testing.T) {
	t.Parallel()
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	if file.Golden.KID == file.RefreshGolden.KID ||
		file.Golden.PublicKeyDERB64URL == file.RefreshGolden.PublicKeyDERB64URL {
		t.Fatal("refresh golden did not rotate its issuer key")
	}
	if err := validateDelegatedMintIssueV1Renewal(file.Golden, file.RefreshGolden); err != nil {
		t.Fatalf("valid key rotation rejected: %v", err)
	}
}

func TestDelegatedMintIssueV1AllowsShorterInitialAuthority(t *testing.T) {
	file, err := DelegatedMintIssueV1()
	if err != nil {
		t.Fatal(err)
	}
	initial, refresh := file.Golden, file.RefreshGolden
	const full = `"authority_expires_at":"2026-09-06T23:15:00Z"`
	const shorter = `"authority_expires_at":"2026-09-06T03:15:00Z"`
	initial.BodyUTF8 = strings.Replace(initial.BodyUTF8, full, shorter, 1)
	refresh.BodyUTF8 = strings.Replace(refresh.BodyUTF8, full, shorter, 1)
	if err := validateDelegatedMintIssueV1Renewal(initial, refresh); err != nil {
		t.Fatalf("shorter authority window rejected: %v", err)
	}
}
