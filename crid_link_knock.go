package conformance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// CRIDLinkKnockV1ArtifactID identifies the CRID link knock artifact: the
	// client contract for asking the server for a qURL link by CRID.
	CRIDLinkKnockV1ArtifactID = "qurl-crid-link-knock-v1-vectors"
	// CRIDLinkKnockV1SchemaVersion is the only schema accepted by this release.
	CRIDLinkKnockV1SchemaVersion = 1

	// CRIDLinkKnockV1AuthServiceID and CRIDLinkKnockV1ResourceID, together with
	// a string under CRIDLinkKnockV1UserDataCRIDKey, make a knock a link
	// request. The resource id is a fixed sentinel, not a resource key.
	CRIDLinkKnockV1AuthServiceID        = "qurl"
	CRIDLinkKnockV1ResourceID           = "qurl-crid"
	CRIDLinkKnockV1UserDataCRIDKey      = "qurl_crid"
	CRIDLinkKnockV1UserDataUserAgentKey = "qurl_user_agent"

	// CRIDLinkKnockV1KnockHeaderType is the packet header type of the request
	// and the value its body repeats as headerType.
	CRIDLinkKnockV1KnockHeaderType = 1
	// CRIDLinkKnockV1ACKHeaderType is the packet header type of the only reply
	// that carries an outcome code.
	CRIDLinkKnockV1ACKHeaderType = 2
	// CRIDLinkKnockV1CookieHeaderType is the packet header type of the overload
	// cookie reply. It is not an ACK, carries no outcome code, and means busy.
	CRIDLinkKnockV1CookieHeaderType = 7
	// CRIDLinkKnockV1UserAgentMaxBytes bounds the UTF-8 length of the user
	// agent a client sends. A longer value is truncated, never rejected.
	CRIDLinkKnockV1UserAgentMaxBytes = 256
	// CRIDLinkKnockV1PublisherNameMaxCodePoints bounds the publisher name a
	// client keeps. A longer name is dropped, never shortened.
	CRIDLinkKnockV1PublisherNameMaxCodePoints = 128
	// CRIDLinkKnockV1LinkOrigin is the link origin of the deployment these
	// vectors model. A client checks an issued link against the link origin of
	// the deployment it is configured for.
	CRIDLinkKnockV1LinkOrigin = "https://qurl.link"

	// CRIDLinkKnockV1CodeLinkIssued is the only code that carries a link. It is
	// deliberately not a success code: the request opens nothing.
	CRIDLinkKnockV1CodeLinkIssued = "52600"

	// The closed client_result vocabulary: every outcome of interpreting a
	// reply. Busy is the one result that does not come from an ACK body; it is
	// the cookie reply. Adding a result requires a schema_version bump.
	CRIDLinkKnockV1ResultLink              = "link"
	CRIDLinkKnockV1ResultUnavailable       = "unavailable"
	CRIDLinkKnockV1ResultNotFound          = "not_found"
	CRIDLinkKnockV1ResultRateLimited       = "rate_limited"
	CRIDLinkKnockV1ResultOffline           = "offline"
	CRIDLinkKnockV1ResultClosed            = "closed"
	CRIDLinkKnockV1ResultInvalid           = "invalid"
	CRIDLinkKnockV1ResultProtocolViolation = "protocol_violation"
	CRIDLinkKnockV1ResultServerError       = "server_error"
	CRIDLinkKnockV1ResultBusy              = "busy"

	// The closed handling vocabulary of reply_type_rules: what a client does
	// with a reply once it has read the packet header type.
	CRIDLinkKnockV1HandlingInterpretACKBody = "interpret_ack_body"
	CRIDLinkKnockV1HandlingClientResult     = "client_result"
	CRIDLinkKnockV1HandlingTransportError   = "transport_error"

	// The closed reject_class vocabulary for an issued link, in reference check
	// order. Adding a class requires a schema_version bump.
	CRIDLinkKnockV1RejectMissingRedirect  = "missing_redirect"
	CRIDLinkKnockV1RejectOrigin           = "origin"
	CRIDLinkKnockV1RejectPathOrQuery      = "path_or_query"
	CRIDLinkKnockV1RejectTransport        = "transport"
	CRIDLinkKnockV1RejectIssuerSignature  = "issuer_signature"
	CRIDLinkKnockV1RejectCRIDMismatch     = "crid_mismatch"
	CRIDLinkKnockV1RejectInfoCRIDMismatch = "info_crid_mismatch"
)

// CRIDLinkKnockV1File freezes the client side of the CRID link request: the
// knock application body, the closed ACK outcome codes, the checks a client
// runs on an issued link, and the handling of unverified display metadata.
type CRIDLinkKnockV1File struct {
	Artifact                      string                              `json:"artifact"`
	SchemaVersion                 int                                 `json:"schema_version"`
	Description                   string                              `json:"description"`
	Notes                         []string                            `json:"notes"`
	Constants                     CRIDLinkKnockV1Constants            `json:"constants"`
	Composes                      CRIDLinkKnockV1Composes             `json:"composes"`
	ReplyTypeRules                CRIDLinkKnockV1ReplyTypeRules       `json:"reply_type_rules"`
	ErrorCodes                    map[string]CRIDLinkKnockV1ErrorCode `json:"error_codes"`
	ClientResults                 []string                            `json:"client_results"`
	RejectClasses                 []string                            `json:"reject_classes"`
	Fixtures                      CRIDLinkKnockV1Fixtures             `json:"fixtures"`
	RequestCases                  []CRIDLinkKnockV1RequestCase        `json:"request_cases"`
	InvalidRequestCases           []CRIDLinkKnockV1InvalidRequestCase `json:"invalid_request_cases"`
	ACKCases                      []CRIDLinkKnockV1ACKCase            `json:"ack_cases"`
	ClientVerificationCases       []CRIDLinkKnockV1VerificationCase   `json:"client_verification_cases"`
	RedirectInfoSanitizationCases []CRIDLinkKnockV1SanitizationCase   `json:"redirect_info_sanitization_cases"`
}

// CRIDLinkKnockV1Constants is the language-neutral request and reply grammar.
type CRIDLinkKnockV1Constants struct {
	AuthServiceID              string                      `json:"auth_service_id"`
	ResourceID                 string                      `json:"resource_id"`
	UserDataKeys               CRIDLinkKnockV1UserDataKeys `json:"user_data_keys"`
	ForbiddenUserDataKeys      []string                    `json:"forbidden_user_data_keys"`
	KnockHeaderType            int                         `json:"knock_header_type"`
	ACKHeaderType              int                         `json:"ack_header_type"`
	CookieHeaderType           int                         `json:"cookie_header_type"`
	UserAgentMaxBytes          int                         `json:"user_agent_max_bytes"`
	PublisherNameMaxCodePoints int                         `json:"publisher_name_max_code_points"`
	LinkOrigin                 string                      `json:"link_origin"`
}

// CRIDLinkKnockV1UserDataKeys names the only two user-data members a v1
// client sends.
type CRIDLinkKnockV1UserDataKeys struct {
	CRID      string `json:"crid"`
	UserAgent string `json:"user_agent"`
}

// CRIDLinkKnockV1Composes names the sibling artifacts this one reuses by
// reference instead of restating: the issuer key that signs the fixture link,
// the transport contract that frames it, and the CRID derivation.
type CRIDLinkKnockV1Composes struct {
	IssuerTrustAnchor string `json:"issuer_trust_anchor"`
	LinkTransport     string `json:"link_transport"`
	CRID              string `json:"crid"`
}

// CRIDLinkKnockV1ReplyTypeRules says how a client treats a reply by its packet
// header type, before it reads any body. Other covers every header type that
// is neither the ACK nor the cookie reply.
type CRIDLinkKnockV1ReplyTypeRules struct {
	ACK    CRIDLinkKnockV1ReplyTypeRule `json:"ack"`
	Cookie CRIDLinkKnockV1ReplyTypeRule `json:"cookie"`
	Other  CRIDLinkKnockV1ReplyTypeRule `json:"other"`
}

// CRIDLinkKnockV1ReplyTypeRule is the handling of one kind of reply.
// HeaderType is absent from the catch-all rule, and ClientResult is present
// only when the handling is a fixed client result.
type CRIDLinkKnockV1ReplyTypeRule struct {
	HeaderType         int    `json:"header_type,omitempty"`
	IsACK              bool   `json:"is_ack"`
	CarriesOutcomeCode bool   `json:"carries_outcome_code"`
	Handling           string `json:"handling"`
	ClientResult       string `json:"client_result,omitempty"`
}

// CRIDLinkKnockV1ErrorCode is one row of the closed ACK outcome table.
type CRIDLinkKnockV1ErrorCode struct {
	Name         string `json:"name"`
	Retryable    bool   `json:"retryable"`
	ClientResult string `json:"client_result"`
}

// CRIDLinkKnockV1Fixtures names the values the cases share. Link is the
// published qURL v2 accept link, and both CRIDs derive from the resource
// public key its signed claims carry.
type CRIDLinkKnockV1Fixtures struct {
	CRID                 string `json:"crid"`
	TestEnvironmentCRID  string `json:"test_environment_crid"`
	UnrelatedCRID        string `json:"unrelated_crid"`
	ResourcePublicKeyB64 string `json:"resource_public_key_b64"`
	Link                 string `json:"link"`
}

// CRIDLinkKnockV1RequestInput is what a caller hands the request builder.
// UserAgent is nil when the caller has none to report.
type CRIDLinkKnockV1RequestInput struct {
	CRID      string  `json:"crid"`
	UserAgent *string `json:"user_agent,omitempty"`
}

// CRIDLinkKnockV1RequestCase pins one request. Body is the application body
// as a JSON object and Serialized is its exact canonical byte form.
type CRIDLinkKnockV1RequestCase struct {
	Name       string                      `json:"name"`
	Input      CRIDLinkKnockV1RequestInput `json:"input"`
	Body       json.RawMessage             `json:"body"`
	Serialized string                      `json:"serialized"`
}

// CRIDLinkKnockV1InvalidRequestCase is an input a client must refuse to send.
// CRIDRejectClass comes from the CRID v1 vocabulary, not from this artifact:
// the class the CRID v1 local gate reports, or version for a well-formed CRID
// whose version the client cannot verify a link against.
type CRIDLinkKnockV1InvalidRequestCase struct {
	Name            string                      `json:"name"`
	Input           CRIDLinkKnockV1RequestInput `json:"input"`
	Outcome         string                      `json:"outcome"`
	CRIDRejectClass string                      `json:"crid_reject_class"`
}

// CRIDLinkKnockV1ACKCase is one already-decrypted ACK body and the result a
// client derives from it for the requested CRID.
type CRIDLinkKnockV1ACKCase struct {
	Name          string                        `json:"name"`
	RequestedCRID string                        `json:"requested_crid"`
	Body          json.RawMessage               `json:"body"`
	Expected      CRIDLinkKnockV1ACKExpectation `json:"expected"`
}

// CRIDLinkKnockV1ACKExpectation is the declared client result. Link and Info
// are present only for the link result.
type CRIDLinkKnockV1ACKExpectation struct {
	ClientResult string                   `json:"client_result"`
	Link         string                   `json:"link,omitempty"`
	Info         *CRIDLinkKnockV1LinkInfo `json:"info,omitempty"`
}

// CRIDLinkKnockV1LinkInfo is the sanitized, display-only view of redirectInfo.
// Nothing in it is covered by the link signature or by the CRID.
type CRIDLinkKnockV1LinkInfo struct {
	QURLID            string                   `json:"qurl_id,omitempty"`
	ExpiresAt         string                   `json:"expires_at,omitempty"`
	ResourceCreatedAt string                   `json:"resource_created_at,omitempty"`
	Publisher         CRIDLinkKnockV1Publisher `json:"publisher"`
}

// CRIDLinkKnockV1Publisher is self-declared, unverified display metadata.
type CRIDLinkKnockV1Publisher struct {
	Name     string `json:"name,omitempty"`
	Verified bool   `json:"verified"`
}

// CRIDLinkKnockV1VerificationCase is one link-issued ACK and whether a client
// may use its link for the requested CRID.
type CRIDLinkKnockV1VerificationCase struct {
	Name          string          `json:"name"`
	RequestedCRID string          `json:"requested_crid"`
	Body          json.RawMessage `json:"body"`
	Outcome       string          `json:"outcome"`
	RejectClass   string          `json:"reject_class,omitempty"`
}

// CRIDLinkKnockV1SanitizationCase is one raw redirectInfo value and the view
// a client keeps. A malformed value degrades; it never fails the request.
type CRIDLinkKnockV1SanitizationCase struct {
	Name         string                  `json:"name"`
	RedirectInfo json.RawMessage         `json:"redirect_info"`
	Expected     CRIDLinkKnockV1LinkInfo `json:"expected"`
}

// cridLinkKnockV1CheckMembers requires the committed document to spell out
// exactly the members its typed form carries. Go decodes a missing false,
// zero or empty value just like an explicit one. Without this gate a
// required member (a retryable flag, a publisher's verified flag, an empty
// CRID input) could vanish from the JSON that every other language reads
// while this loader stayed green. The reverse direction keeps optional
// members canonical: they are omitted, never written as empty or null.
func cridLinkKnockV1CheckMembers(data []byte, typed any) error {
	encoded, err := json.Marshal(typed)
	if err != nil {
		return err
	}
	var want, got any
	if err := json.Unmarshal(encoded, &want); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &got); err != nil {
		return err
	}
	return cridLinkKnockV1CompareMembers("", want, got)
}

func cridLinkKnockV1CompareMembers(path string, typed, raw any) error {
	switch typedValue := typed.(type) {
	case map[string]any:
		rawValue, ok := raw.(map[string]any)
		if !ok {
			return nil
		}
		for _, key := range slices.Sorted(maps.Keys(typedValue)) {
			member, present := rawValue[key]
			if !present {
				return fmt.Errorf("conformance: CRID link knock file omits required member %s", path+key)
			}
			if err := cridLinkKnockV1CompareMembers(path+key+".", typedValue[key], member); err != nil {
				return err
			}
		}
		for _, key := range slices.Sorted(maps.Keys(rawValue)) {
			if _, present := typedValue[key]; !present {
				return fmt.Errorf("conformance: CRID link knock file writes optional member %s as empty instead of omitting it", path+key)
			}
		}
	case []any:
		rawValue, ok := raw.([]any)
		if !ok {
			return nil
		}
		for i := 0; i < len(typedValue) && i < len(rawValue); i++ {
			if err := cridLinkKnockV1CompareMembers(path+strconv.Itoa(i)+".", typedValue[i], rawValue[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

var (
	cridLinkKnockV1ForbiddenUserDataKeys = []string{
		"qurl_access_token", "qurl_claims_b64", "qurl_issuer_sig_b64", "qurl_passkey",
	}

	cridLinkKnockV1ErrorCodes = map[string]CRIDLinkKnockV1ErrorCode{
		CRIDLinkKnockV1CodeLinkIssued: {Name: "link_issued", Retryable: false, ClientResult: CRIDLinkKnockV1ResultLink},
		"52601":                       {Name: "unavailable", Retryable: true, ClientResult: CRIDLinkKnockV1ResultUnavailable},
		"52602":                       {Name: "not_found", Retryable: false, ClientResult: CRIDLinkKnockV1ResultNotFound},
		"52603":                       {Name: "rate_limited", Retryable: true, ClientResult: CRIDLinkKnockV1ResultRateLimited},
		"52604":                       {Name: "resource_offline", Retryable: true, ClientResult: CRIDLinkKnockV1ResultOffline},
		"52605":                       {Name: "resource_closed", Retryable: false, ClientResult: CRIDLinkKnockV1ResultClosed},
		"52606":                       {Name: "invalid_request", Retryable: false, ClientResult: CRIDLinkKnockV1ResultInvalid},
	}

	cridLinkKnockV1ClientResults = []string{
		CRIDLinkKnockV1ResultLink, CRIDLinkKnockV1ResultUnavailable, CRIDLinkKnockV1ResultNotFound,
		CRIDLinkKnockV1ResultRateLimited, CRIDLinkKnockV1ResultOffline, CRIDLinkKnockV1ResultClosed,
		CRIDLinkKnockV1ResultInvalid, CRIDLinkKnockV1ResultProtocolViolation, CRIDLinkKnockV1ResultServerError,
		CRIDLinkKnockV1ResultBusy,
	}

	cridLinkKnockV1ReplyTypeRules = CRIDLinkKnockV1ReplyTypeRules{
		ACK: CRIDLinkKnockV1ReplyTypeRule{
			HeaderType:         CRIDLinkKnockV1ACKHeaderType,
			IsACK:              true,
			CarriesOutcomeCode: true,
			Handling:           CRIDLinkKnockV1HandlingInterpretACKBody,
		},
		Cookie: CRIDLinkKnockV1ReplyTypeRule{
			HeaderType:   CRIDLinkKnockV1CookieHeaderType,
			Handling:     CRIDLinkKnockV1HandlingClientResult,
			ClientResult: CRIDLinkKnockV1ResultBusy,
		},
		Other: CRIDLinkKnockV1ReplyTypeRule{Handling: CRIDLinkKnockV1HandlingTransportError},
	}

	cridLinkKnockV1RejectClasses = []string{
		CRIDLinkKnockV1RejectMissingRedirect, CRIDLinkKnockV1RejectOrigin, CRIDLinkKnockV1RejectPathOrQuery,
		CRIDLinkKnockV1RejectTransport, CRIDLinkKnockV1RejectIssuerSignature, CRIDLinkKnockV1RejectCRIDMismatch,
		CRIDLinkKnockV1RejectInfoCRIDMismatch,
	}

	cridLinkKnockV1Composition = CRIDLinkKnockV1Composes{
		IssuerTrustAnchor: strings.TrimPrefix(issuerSignatureName, "vectors/"),
		LinkTransport:     strings.TrimPrefix(conformanceVectorsName, "vectors/"),
		CRID:              strings.TrimPrefix(cridV1Name, "vectors/"),
	}
)

// Frozen fixture inputs. The link, its CRIDs and its expiry are not listed
// here: they are read from the sibling artifacts so one copy of the signed
// bytes stays authoritative.
const (
	cridLinkKnockV1PublishedLinkVector = "accept_valid_qv2_round_trip"

	cridLinkKnockV1FixtureQURLID              = "q_a1b2c3d4e5f"
	cridLinkKnockV1FixtureResourceCreatedAt   = "2026-06-18T09:30:00Z"
	cridLinkKnockV1FixtureResourceCreatedUnix = "1781775000"
	cridLinkKnockV1FixturePublisherName       = "Example Publisher"
	cridLinkKnockV1FixtureAgentAddr           = "203.0.113.9:49152"
	cridLinkKnockV1FixtureLinkIssuedMessage   = "crid link issued"

	cridLinkKnockV1UserAgentBrowser = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
	// A quote and a backslash are the only characters here that JSON must
	// escape; the solidus and the HTML characters must stay as they are.
	cridLinkKnockV1UserAgentEscaping = `qurl-conformance/1.0 "quoted" back\slash <tag> a&b`
)

var (
	// 31 prefix bytes (the u-umlaut is two) plus 225: exactly at the limit.
	cridLinkKnockV1UserAgentAtLimit = "qurl-conformance/1.0 (Zürich) " + strings.Repeat("a", 225)
	// 300 ASCII bytes.
	cridLinkKnockV1UserAgentOverLimit = "qurl-conformance/1.0 (ascii) " + strings.Repeat("b", 271)
	// 253 ASCII bytes, then one four-byte character that straddles the limit,
	// then one more byte: 258 bytes but only 256 UTF-16 code units.
	cridLinkKnockV1UserAgentBoundary = "qurl-conformance/1.0 (boundary) " + strings.Repeat("c", 221) + "\U0001F600c"

	// 128 code points that are 131 bytes and 129 UTF-16 code units.
	cridLinkKnockV1PublisherNameAtLimit   = strings.Repeat("a", CRIDLinkKnockV1PublisherNameMaxCodePoints-1) + "\U00020000"
	cridLinkKnockV1PublisherNameOverLimit = strings.Repeat("a", CRIDLinkKnockV1PublisherNameMaxCodePoints+1)

	cridLinkKnockV1RequestFixtures = map[string]*string{
		"minimal":                  nil,
		"with_user_agent":          cridLinkKnockV1StringPointer(cridLinkKnockV1UserAgentBrowser),
		"user_agent_json_escaping": cridLinkKnockV1StringPointer(cridLinkKnockV1UserAgentEscaping),
		"user_agent_at_limit":      &cridLinkKnockV1UserAgentAtLimit,
		"user_agent_truncated":     &cridLinkKnockV1UserAgentOverLimit,
		"user_agent_truncated_at_code_point_boundary": &cridLinkKnockV1UserAgentBoundary,
	}

	cridLinkKnockV1InvalidRequestFixtures = map[string]func(env *cridLinkKnockV1Environment) string{
		"reject_checksum": func(env *cridLinkKnockV1Environment) string {
			// One changed character inside the digest keeps the alphabet, the
			// length and the pad bits intact, so only the checksum can object.
			replacement := byte('b')
			if env.crid[20] == replacement {
				replacement = 'c'
			}
			return env.crid[:20] + string(replacement) + env.crid[21:]
		},
		"reject_wrong_length": func(env *cridLinkKnockV1Environment) string { return env.crid[:len(env.crid)-1] },
		"reject_uppercase":    func(env *cridLinkKnockV1Environment) string { return strings.ToUpper(env.crid) },
		"reject_empty":        func(*cridLinkKnockV1Environment) string { return "" },
		// The fixture resource key under versions a client cannot verify a
		// link against: one unregistered byte in the full form, and the two
		// reserved bytes in their short form. All three are well-formed CRIDs
		// with a valid checksum.
		"reject_unregistered_version": func(env *cridLinkKnockV1Environment) string {
			return env.deriveCRID(0x7f, CRIDV1FullDigestLength)
		},
		"reject_reserved_version_02": func(env *cridLinkKnockV1Environment) string {
			return env.deriveCRID(0x02, CRIDV1TruncatedDigestLength)
		},
		"reject_reserved_version_82": func(env *cridLinkKnockV1Environment) string {
			return env.deriveCRID(0x82, CRIDV1TruncatedDigestLength)
		},
	}
)

func cridLinkKnockV1StringPointer(value string) *string { return &value }

// cridLinkKnockV1Environment is everything the reference checks borrow from
// the sibling artifacts: the published qv2t1 link with its transport contract
// and the issuer key that signs it. Reading them here, rather than restating
// them, means a regenerated link cannot leave this family verifying stale
// bytes.
type cridLinkKnockV1Environment struct {
	transportContract ConformanceTransportContract
	transport         string
	canonical         string
	signingPrefix     string
	issuerPublic      *ecdsa.PublicKey
	resourceKeyB64    string
	resourceDER       []byte
	expiresUnix       int64
	crid              string
	testCRID          string
	unrelatedCRID     string
}

type cridLinkKnockV1LinkClaims struct {
	Expiry               int64  `json:"exp"`
	ResourcePublicKeyB64 string `json:"resource_public_key_b64"`
}

func loadCRIDLinkKnockV1Environment() (*cridLinkKnockV1Environment, error) {
	qv2, err := ConformanceVectors()
	if err != nil {
		return nil, fmt.Errorf("conformance: CRID link knock composes an unreadable link artifact: %w", err)
	}
	issuer, err := SignatureVectors()
	if err != nil {
		return nil, fmt.Errorf("conformance: CRID link knock composes an unreadable trust anchor: %w", err)
	}
	env := &cridLinkKnockV1Environment{
		transportContract: qv2.TransportContract,
		signingPrefix:     issuer.DomainSeparationPrefix,
		unrelatedCRID:     cridV1ProdCanonicalCRID,
	}
	for _, vector := range qv2.Classes["transport"].Vectors {
		if vector.Name == cridLinkKnockV1PublishedLinkVector && vector.Expect == ExpectAccept {
			env.transport, env.canonical = vector.TransportFragment, vector.CanonicalFragment
		}
	}
	if env.transport == "" {
		return nil, fmt.Errorf("conformance: CRID link knock cannot find the published link vector %q", cridLinkKnockV1PublishedLinkVector)
	}
	der, err := strictRawBase64URL(issuer.Issuer.SPKIDERB64)
	if err != nil {
		return nil, errors.New("conformance: CRID link knock trust anchor is not canonical base64url")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	public, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || public.Curve != elliptic.P256() {
		return nil, errors.New("conformance: CRID link knock trust anchor is not a P-256 public key")
	}
	env.issuerPublic = public

	canonical, claims, class := env.openLink(CRIDLinkKnockV1LinkOrigin + "/#" + env.transport)
	if class != "" || canonical != env.canonical {
		return nil, fmt.Errorf("conformance: CRID link knock published link does not verify under its trust anchor (%q)", class)
	}
	resourceDER, err := strictRawBase64URL(claims.ResourcePublicKeyB64)
	if err != nil || len(resourceDER) == 0 || claims.Expiry <= 0 {
		return nil, errors.New("conformance: CRID link knock published link claims carry no usable resource key or expiry")
	}
	env.resourceKeyB64 = claims.ResourcePublicKeyB64
	env.resourceDER = resourceDER
	env.expiresUnix = claims.Expiry
	env.crid = env.deriveCRID(0x01, CRIDV1FullDigestLength)
	env.testCRID = env.deriveCRID(0x81, CRIDV1FullDigestLength)
	return env, nil
}

// deriveCRID is the CRID of the fixture resource key under a version byte and
// digest length.
func (env *cridLinkKnockV1Environment) deriveCRID(version byte, digestLength int) string {
	_, _, _, crid := deriveCRIDV1(version, env.resourceDER, digestLength)
	return crid
}

func (env *cridLinkKnockV1Environment) link() string {
	return CRIDLinkKnockV1LinkOrigin + "/#" + env.transport
}

func (env *cridLinkKnockV1Environment) expiresAt() string {
	return time.Unix(env.expiresUnix, 0).UTC().Format(time.RFC3339)
}

// tamperedTransport is the published transport with the first character of
// its signature component swapped. The top six bits of r change, so the
// signature stays a well-formed low-S value that simply does not verify.
func (env *cridLinkKnockV1Environment) tamperedTransport() string {
	cut := strings.LastIndexByte(env.transport, '.') + 1
	replacement := "A"
	if env.transport[cut] == 'A' {
		replacement = "B"
	}
	return env.transport[:cut] + replacement + env.transport[cut+1:]
}

// ParseCRIDLinkKnockV1File strictly parses the CRID link knock artifact and
// re-derives every declared expectation with reference implementations: the
// canonical request bytes and user-agent truncation, the request gate for
// refused inputs, the client result of every ACK, the reject class of every
// issued link (including a real issuer-signature check against the composed
// trust anchor and a real CRID derivation from the signed resource key), and
// the sanitized view of every redirectInfo value.
func ParseCRIDLinkKnockV1File(data []byte) (*CRIDLinkKnockV1File, error) {
	var lf CRIDLinkKnockV1File
	if err := strictDecodeArtifact(data, &lf); err != nil {
		return nil, fmt.Errorf("conformance: parse CRID link knock file: %w", err)
	}
	if err := cridLinkKnockV1CheckMembers(data, &lf); err != nil {
		return nil, err
	}
	if lf.Artifact != CRIDLinkKnockV1ArtifactID {
		return nil, fmt.Errorf("conformance: CRID link knock file has artifact %q, want %q", lf.Artifact, CRIDLinkKnockV1ArtifactID)
	}
	if lf.SchemaVersion != CRIDLinkKnockV1SchemaVersion {
		return nil, fmt.Errorf("conformance: CRID link knock file has schema_version %d, want %d", lf.SchemaVersion, CRIDLinkKnockV1SchemaVersion)
	}
	if lf.Description == "" || len(lf.Notes) == 0 || slices.Contains(lf.Notes, "") {
		return nil, errors.New("conformance: CRID link knock file has an empty description or notes")
	}
	if err := validateCRIDLinkKnockV1Vocabularies(&lf); err != nil {
		return nil, err
	}
	env, err := loadCRIDLinkKnockV1Environment()
	if err != nil {
		return nil, err
	}
	for _, fixture := range []struct{ name, got, want string }{
		{"link", lf.Fixtures.Link, env.link()},
		{"resource_public_key_b64", lf.Fixtures.ResourcePublicKeyB64, env.resourceKeyB64},
		{"crid", lf.Fixtures.CRID, env.crid},
		{"test_environment_crid", lf.Fixtures.TestEnvironmentCRID, env.testCRID},
		{"unrelated_crid", lf.Fixtures.UnrelatedCRID, env.unrelatedCRID},
	} {
		if fixture.got != fixture.want {
			return nil, fmt.Errorf("conformance: CRID link knock fixtures.%s does not re-derive from the published link", fixture.name)
		}
	}
	if err := env.validateRequestCases(lf.RequestCases); err != nil {
		return nil, err
	}
	if err := env.validateInvalidRequestCases(lf.InvalidRequestCases); err != nil {
		return nil, err
	}
	if err := env.validateACKCases(lf.ACKCases); err != nil {
		return nil, err
	}
	if err := env.validateVerificationCases(lf.ClientVerificationCases); err != nil {
		return nil, err
	}
	if err := env.validateSanitizationCases(lf.RedirectInfoSanitizationCases); err != nil {
		return nil, err
	}
	return &lf, nil
}

func validateCRIDLinkKnockV1Vocabularies(lf *CRIDLinkKnockV1File) error {
	wantConstants := CRIDLinkKnockV1Constants{
		AuthServiceID: CRIDLinkKnockV1AuthServiceID,
		ResourceID:    CRIDLinkKnockV1ResourceID,
		UserDataKeys: CRIDLinkKnockV1UserDataKeys{
			CRID:      CRIDLinkKnockV1UserDataCRIDKey,
			UserAgent: CRIDLinkKnockV1UserDataUserAgentKey,
		},
		ForbiddenUserDataKeys:      cridLinkKnockV1ForbiddenUserDataKeys,
		KnockHeaderType:            CRIDLinkKnockV1KnockHeaderType,
		ACKHeaderType:              CRIDLinkKnockV1ACKHeaderType,
		CookieHeaderType:           CRIDLinkKnockV1CookieHeaderType,
		UserAgentMaxBytes:          CRIDLinkKnockV1UserAgentMaxBytes,
		PublisherNameMaxCodePoints: CRIDLinkKnockV1PublisherNameMaxCodePoints,
		LinkOrigin:                 CRIDLinkKnockV1LinkOrigin,
	}
	if !reflect.DeepEqual(lf.Constants, wantConstants) {
		return fmt.Errorf("conformance: CRID link knock constants = %+v, want %+v", lf.Constants, wantConstants)
	}
	if lf.Composes != cridLinkKnockV1Composition {
		return fmt.Errorf("conformance: CRID link knock composes = %+v, want %+v", lf.Composes, cridLinkKnockV1Composition)
	}
	if lf.ReplyTypeRules != cridLinkKnockV1ReplyTypeRules {
		return fmt.Errorf("conformance: CRID link knock reply_type_rules = %+v, want %+v", lf.ReplyTypeRules, cridLinkKnockV1ReplyTypeRules)
	}
	if !maps.Equal(lf.ErrorCodes, cridLinkKnockV1ErrorCodes) {
		return fmt.Errorf("conformance: CRID link knock error_codes = %+v, want %+v", lf.ErrorCodes, cridLinkKnockV1ErrorCodes)
	}
	if !slices.Equal(lf.ClientResults, cridLinkKnockV1ClientResults) {
		return fmt.Errorf("conformance: CRID link knock client_results = %v, want %v", lf.ClientResults, cridLinkKnockV1ClientResults)
	}
	if !slices.Equal(lf.RejectClasses, cridLinkKnockV1RejectClasses) {
		return fmt.Errorf("conformance: CRID link knock reject_classes = %v, want %v", lf.RejectClasses, cridLinkKnockV1RejectClasses)
	}
	return nil
}

// cridLinkKnockV1CheckCaseSet enforces a closed case set: every fixture name
// exactly once, and nothing else.
func cridLinkKnockV1CheckCaseSet[C, F any](kind string, cases []C, fixtures map[string]F, name func(C) string) error {
	if len(cases) != len(fixtures) {
		return fmt.Errorf("conformance: CRID link knock %s case count = %d, want %d", kind, len(cases), len(fixtures))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		if _, known := fixtures[name(c)]; !known {
			return fmt.Errorf("conformance: unknown CRID link knock %s case %q", kind, name(c))
		}
		if _, duplicate := seen[name(c)]; duplicate {
			return fmt.Errorf("conformance: duplicate CRID link knock %s case %q", kind, name(c))
		}
		seen[name(c)] = struct{}{}
	}
	return nil
}

func (env *cridLinkKnockV1Environment) validateRequestCases(cases []CRIDLinkKnockV1RequestCase) error {
	if err := cridLinkKnockV1CheckCaseSet("request", cases, cridLinkKnockV1RequestFixtures, func(c CRIDLinkKnockV1RequestCase) string { return c.Name }); err != nil {
		return err
	}
	for _, c := range cases {
		userAgent := cridLinkKnockV1RequestFixtures[c.Name]
		if c.Input.CRID != env.crid || !equalOptionalString(c.Input.UserAgent, userAgent) {
			return fmt.Errorf("conformance: CRID link knock request case %q input does not match its fixture", c.Name)
		}
		serialized, sent, err := cridLinkKnockV1SerializeRequest(c.Input)
		if err != nil {
			return fmt.Errorf("conformance: CRID link knock request case %q: %w", c.Name, err)
		}
		if len(sent) > CRIDLinkKnockV1UserAgentMaxBytes || !utf8.ValidString(sent) {
			return fmt.Errorf("conformance: CRID link knock request case %q sends a user agent that is over %d bytes or not valid UTF-8", c.Name, CRIDLinkKnockV1UserAgentMaxBytes)
		}
		if c.Serialized != serialized {
			return fmt.Errorf("conformance: CRID link knock request case %q serialized does not re-derive from its input", c.Name)
		}
		// The body object is committed in canonical member order, so removing
		// its insignificant whitespace must reproduce the canonical bytes.
		var compact bytes.Buffer
		if err := json.Compact(&compact, c.Body); err != nil || compact.String() != c.Serialized {
			return fmt.Errorf("conformance: CRID link knock request case %q body does not serialize to its serialized form", c.Name)
		}
	}
	return nil
}

func (env *cridLinkKnockV1Environment) validateInvalidRequestCases(cases []CRIDLinkKnockV1InvalidRequestCase) error {
	if err := cridLinkKnockV1CheckCaseSet("invalid request", cases, cridLinkKnockV1InvalidRequestFixtures, func(c CRIDLinkKnockV1InvalidRequestCase) string { return c.Name }); err != nil {
		return err
	}
	for _, c := range cases {
		build := cridLinkKnockV1InvalidRequestFixtures[c.Name]
		if c.Input.CRID != build(env) || c.Input.UserAgent != nil {
			return fmt.Errorf("conformance: CRID link knock invalid request case %q input does not match its fixture", c.Name)
		}
		outcome, rejectClass := cridLinkKnockV1RequestExpectation(c.Input.CRID)
		if outcome != ExpectReject || c.Outcome != outcome || c.CRIDRejectClass != rejectClass {
			return fmt.Errorf("conformance: CRID link knock invalid request case %q expectation = %q/%q, want %q/%q", c.Name, c.Outcome, c.CRIDRejectClass, outcome, rejectClass)
		}
	}
	return nil
}

type cridLinkKnockV1ACKFixture struct {
	body   map[string]any
	result string
}

func (env *cridLinkKnockV1Environment) redirectInfo(crid string) map[string]any {
	return map[string]any{
		"crid":                crid,
		"qurl_id":             cridLinkKnockV1FixtureQURLID,
		"expires_at":          env.expiresAt(),
		"resource_created_at": cridLinkKnockV1FixtureResourceCreatedAt,
		"publisher":           cridLinkKnockV1FixturePublisher(),
	}
}

func cridLinkKnockV1FixturePublisher() map[string]any {
	return map[string]any{"name": cridLinkKnockV1FixturePublisherName, "verified": false}
}

// cridLinkKnockV1ACK builds an ACK body in the denial shape: nothing opened,
// no session, no routing. Extra members are alternating key/value pairs.
func cridLinkKnockV1ACK(code, message string, members ...any) map[string]any {
	ack := map[string]any{
		"errCode":   code,
		"resHost":   nil,
		"opnTime":   json.Number("0"),
		"agentAddr": cridLinkKnockV1FixtureAgentAddr,
		"acTokens":  nil,
	}
	if message != "" {
		ack["errMsg"] = message
	}
	for i := 0; i+1 < len(members); i += 2 {
		ack[members[i].(string)] = members[i+1]
	}
	return ack
}

func (env *cridLinkKnockV1Environment) linkACK(redirect any, info any) map[string]any {
	return cridLinkKnockV1ACK(CRIDLinkKnockV1CodeLinkIssued, cridLinkKnockV1FixtureLinkIssuedMessage,
		"redirectUrl", redirect, "redirectInfo", info)
}

// cridLinkKnockV1With returns a copy of an object with one member replaced.
func cridLinkKnockV1With(object map[string]any, key string, value any) map[string]any {
	copied := make(map[string]any, len(object)+1)
	for k, v := range object {
		copied[k] = v
	}
	copied[key] = value
	return copied
}

// cridLinkKnockV1Without returns a copy of an object with one member removed.
func cridLinkKnockV1Without(object map[string]any, key string) map[string]any {
	copied := cridLinkKnockV1With(object, key, nil)
	delete(copied, key)
	return copied
}

func (env *cridLinkKnockV1Environment) ackFixtures() map[string]cridLinkKnockV1ACKFixture {
	info := env.redirectInfo(env.crid)
	link := env.link()
	denial := cridLinkKnockV1ACK
	return map[string]cridLinkKnockV1ACKFixture{
		"link_issued": {env.linkACK(link, info), CRIDLinkKnockV1ResultLink},
		"link_issued_without_publisher_name": {
			env.linkACK(link, cridLinkKnockV1With(info, "publisher", map[string]any{"verified": false})),
			CRIDLinkKnockV1ResultLink,
		},
		"link_issued_without_redirect_info": {
			cridLinkKnockV1Without(env.linkACK(link, nil), "redirectInfo"),
			CRIDLinkKnockV1ResultLink,
		},
		"denied_unavailable":      {denial("52601", "crid link unavailable"), CRIDLinkKnockV1ResultUnavailable},
		"denied_not_found":        {denial("52602", "crid link not found"), CRIDLinkKnockV1ResultNotFound},
		"denied_rate_limited":     {denial("52603", "crid link rate limited"), CRIDLinkKnockV1ResultRateLimited},
		"denied_resource_offline": {denial("52604", "crid link resource offline"), CRIDLinkKnockV1ResultOffline},
		"denied_resource_closed":  {denial("52605", "crid link resource closed"), CRIDLinkKnockV1ResultClosed},
		"denied_invalid_request":  {denial("52606", "invalid crid link request"), CRIDLinkKnockV1ResultInvalid},
		"denied_with_redirect_is_not_a_link": {
			cridLinkKnockV1ACK("52602", "crid link not found", "redirectUrl", link, "redirectInfo", info),
			CRIDLinkKnockV1ResultNotFound,
		},
		"success_code_is_protocol_violation": {
			cridLinkKnockV1ACK("0", "", "redirectUrl", link, "redirectInfo", info),
			CRIDLinkKnockV1ResultProtocolViolation,
		},
		"empty_code_is_protocol_violation": {cridLinkKnockV1ACK("", ""), CRIDLinkKnockV1ResultProtocolViolation},
		"missing_code_is_protocol_violation": {
			cridLinkKnockV1Without(cridLinkKnockV1ACK("", ""), "errCode"),
			CRIDLinkKnockV1ResultProtocolViolation,
		},
		// The link-issued body with nothing wrong except the type of its code:
		// a client that coerces the number would hand out the link.
		"numeric_code_is_protocol_violation": {
			cridLinkKnockV1With(env.linkACK(link, info), "errCode", json.Number(CRIDLinkKnockV1CodeLinkIssued)),
			CRIDLinkKnockV1ResultProtocolViolation,
		},
		"null_code_is_protocol_violation": {
			cridLinkKnockV1With(cridLinkKnockV1ACK("", ""), "errCode", nil),
			CRIDLinkKnockV1ResultProtocolViolation,
		},
		"unassigned_code_is_server_error":   {denial("52607", "example unassigned code"), CRIDLinkKnockV1ResultServerError},
		"other_denial_code_is_server_error": {denial("52004", "failed to find resource"), CRIDLinkKnockV1ResultServerError},
	}
}

func (env *cridLinkKnockV1Environment) validateACKCases(cases []CRIDLinkKnockV1ACKCase) error {
	fixtures := env.ackFixtures()
	if err := cridLinkKnockV1CheckCaseSet("ACK", cases, fixtures, func(c CRIDLinkKnockV1ACKCase) string { return c.Name }); err != nil {
		return err
	}
	for _, c := range cases {
		fixture := fixtures[c.Name]
		if c.RequestedCRID != env.crid || !cridLinkKnockV1JSONMatches(c.Body, fixture.body) {
			return fmt.Errorf("conformance: CRID link knock ACK case %q input does not match its fixture", c.Name)
		}
		if !slices.Contains(cridLinkKnockV1ClientResults, c.Expected.ClientResult) {
			return fmt.Errorf("conformance: CRID link knock ACK case %q has unknown client_result %q", c.Name, c.Expected.ClientResult)
		}
		want, rejectClass, err := env.interpretACK(c.RequestedCRID, c.Body)
		if err != nil {
			return fmt.Errorf("conformance: CRID link knock ACK case %q: %w", c.Name, err)
		}
		if rejectClass != "" || want.ClientResult != fixture.result {
			return fmt.Errorf("conformance: CRID link knock ACK case %q derives %q (reject class %q), want %q", c.Name, want.ClientResult, rejectClass, fixture.result)
		}
		if !reflect.DeepEqual(c.Expected, want) {
			return fmt.Errorf("conformance: CRID link knock ACK case %q expectation = %s, want %s", c.Name, cridLinkKnockV1Describe(c.Expected), cridLinkKnockV1Describe(want))
		}
	}
	return nil
}

type cridLinkKnockV1VerificationFixture struct {
	requestedCRID string
	body          map[string]any
	rejectClass   string
}

func (env *cridLinkKnockV1Environment) verificationFixtures() map[string]cridLinkKnockV1VerificationFixture {
	info := env.redirectInfo(env.crid)
	origin := CRIDLinkKnockV1LinkOrigin
	redirect := func(value any, rejectClass string) cridLinkKnockV1VerificationFixture {
		return cridLinkKnockV1VerificationFixture{env.crid, env.linkACK(value, info), rejectClass}
	}
	return map[string]cridLinkKnockV1VerificationFixture{
		"accept_link": redirect(env.link(), ""),
		"accept_redirect_info_without_crid": {
			env.crid, env.linkACK(env.link(), cridLinkKnockV1Without(info, "crid")), "",
		},
		"accept_test_environment_crid": {
			env.testCRID, env.linkACK(env.link(), env.redirectInfo(env.testCRID)), "",
		},
		"reject_missing_redirect": {
			env.crid, cridLinkKnockV1Without(env.linkACK(nil, info), "redirectUrl"), CRIDLinkKnockV1RejectMissingRedirect,
		},
		"reject_null_redirect":         redirect(nil, CRIDLinkKnockV1RejectMissingRedirect),
		"reject_non_string_redirect":   redirect([]any{env.link()}, CRIDLinkKnockV1RejectMissingRedirect),
		"reject_empty_redirect":        redirect("", CRIDLinkKnockV1RejectMissingRedirect),
		"reject_origin_lookalike_host": redirect("https://qurl.link.example.com/#"+env.transport, CRIDLinkKnockV1RejectOrigin),
		"reject_origin_http_scheme":    redirect("http://qurl.link/#"+env.transport, CRIDLinkKnockV1RejectOrigin),
		"reject_origin_other_port":     redirect("https://qurl.link:8443/#"+env.transport, CRIDLinkKnockV1RejectOrigin),
		"reject_origin_userinfo":       redirect("https://user@qurl.link/#"+env.transport, CRIDLinkKnockV1RejectOrigin),
		"reject_path":                  redirect(origin+"/open#"+env.transport, CRIDLinkKnockV1RejectPathOrQuery),
		"reject_query":                 redirect(origin+"/?next=open#"+env.transport, CRIDLinkKnockV1RejectPathOrQuery),
		"reject_legacy_fragment":       redirect(origin+"/#"+env.canonical, CRIDLinkKnockV1RejectTransport),
		"reject_missing_fragment":      redirect(origin+"/", CRIDLinkKnockV1RejectTransport),
		"reject_tampered_signature":    redirect(origin+"/#"+env.tamperedTransport(), CRIDLinkKnockV1RejectIssuerSignature),
		"reject_link_for_another_crid": {
			env.unrelatedCRID, env.linkACK(env.link(), env.redirectInfo(env.unrelatedCRID)), CRIDLinkKnockV1RejectCRIDMismatch,
		},
		"reject_redirect_info_crid_mismatch": {
			env.crid, env.linkACK(env.link(), env.redirectInfo(env.testCRID)), CRIDLinkKnockV1RejectInfoCRIDMismatch,
		},
		// Present but not a string is still present: zero and null are falsy,
		// and the object even holds the right CRID, yet none of them is it.
		"reject_redirect_info_crid_number": {
			env.crid, env.linkACK(env.link(), cridLinkKnockV1With(info, "crid", json.Number("0"))), CRIDLinkKnockV1RejectInfoCRIDMismatch,
		},
		"reject_redirect_info_crid_null": {
			env.crid, env.linkACK(env.link(), cridLinkKnockV1With(info, "crid", nil)), CRIDLinkKnockV1RejectInfoCRIDMismatch,
		},
		"reject_redirect_info_crid_object": {
			env.crid, env.linkACK(env.link(), cridLinkKnockV1With(info, "crid", map[string]any{"value": env.crid})), CRIDLinkKnockV1RejectInfoCRIDMismatch,
		},
	}
}

func (env *cridLinkKnockV1Environment) validateVerificationCases(cases []CRIDLinkKnockV1VerificationCase) error {
	fixtures := env.verificationFixtures()
	if err := cridLinkKnockV1CheckCaseSet("verification", cases, fixtures, func(c CRIDLinkKnockV1VerificationCase) string { return c.Name }); err != nil {
		return err
	}
	for _, c := range cases {
		fixture := fixtures[c.Name]
		if c.RequestedCRID != fixture.requestedCRID || !cridLinkKnockV1JSONMatches(c.Body, fixture.body) {
			return fmt.Errorf("conformance: CRID link knock verification case %q input does not match its fixture", c.Name)
		}
		if c.RejectClass != "" && !slices.Contains(cridLinkKnockV1RejectClasses, c.RejectClass) {
			return fmt.Errorf("conformance: CRID link knock verification case %q has unknown reject_class %q", c.Name, c.RejectClass)
		}
		result, rejectClass, err := env.interpretACK(c.RequestedCRID, c.Body)
		if err != nil {
			return fmt.Errorf("conformance: CRID link knock verification case %q: %w", c.Name, err)
		}
		if rejectClass != fixture.rejectClass || (rejectClass == "" && result.ClientResult != CRIDLinkKnockV1ResultLink) {
			return fmt.Errorf("conformance: CRID link knock verification case %q derives %q/%q, want reject class %q", c.Name, result.ClientResult, rejectClass, fixture.rejectClass)
		}
		wantOutcome := ExpectAccept
		if rejectClass != "" {
			wantOutcome = ExpectReject
		}
		if c.Outcome != wantOutcome || c.RejectClass != rejectClass {
			return fmt.Errorf("conformance: CRID link knock verification case %q expectation = %q/%q, want %q/%q", c.Name, c.Outcome, c.RejectClass, wantOutcome, rejectClass)
		}
	}
	return nil
}

func (env *cridLinkKnockV1Environment) sanitizationFixtures() map[string]any {
	info := env.redirectInfo(env.crid)
	publisher := func(members map[string]any) map[string]any { return cridLinkKnockV1With(info, "publisher", members) }
	named := func(name any) map[string]any { return publisher(map[string]any{"name": name, "verified": false}) }
	return map[string]any{
		"full_info":                   info,
		"info_null":                   nil,
		"info_not_an_object":          cridLinkKnockV1FixturePublisherName,
		"info_array":                  []any{info},
		"publisher_missing":           cridLinkKnockV1Without(info, "publisher"),
		"publisher_not_an_object":     cridLinkKnockV1With(info, "publisher", cridLinkKnockV1FixturePublisherName),
		"publisher_verified_string":   publisher(map[string]any{"name": cridLinkKnockV1FixturePublisherName, "verified": "true"}),
		"publisher_verified_missing":  publisher(map[string]any{"name": cridLinkKnockV1FixturePublisherName}),
		"publisher_name_not_a_string": named(json.Number("42")),
		"publisher_name_empty":        named(""),
		"publisher_name_at_limit":     named(cridLinkKnockV1PublisherNameAtLimit),
		"publisher_name_over_limit":   named(cridLinkKnockV1PublisherNameOverLimit),
		"timestamps_not_strings": cridLinkKnockV1With(
			cridLinkKnockV1With(info, "expires_at", json.Number(strconv.FormatInt(env.expiresUnix, 10))),
			"resource_created_at", map[string]any{"seconds": json.Number(cridLinkKnockV1FixtureResourceCreatedUnix)},
		),
		"qurl_id_not_a_string": cridLinkKnockV1With(info, "qurl_id", json.Number("12345")),
		"empty_strings_are_absent": cridLinkKnockV1With(
			cridLinkKnockV1With(cridLinkKnockV1With(info, "qurl_id", ""), "expires_at", ""),
			"resource_created_at", "",
		),
		"unknown_fields_ignored": cridLinkKnockV1With(
			publisher(cridLinkKnockV1With(cridLinkKnockV1FixturePublisher(), "badge", "gold")),
			"future_field", map[string]any{"enabled": true},
		),
	}
}

func (env *cridLinkKnockV1Environment) validateSanitizationCases(cases []CRIDLinkKnockV1SanitizationCase) error {
	fixtures := env.sanitizationFixtures()
	if err := cridLinkKnockV1CheckCaseSet("sanitization", cases, fixtures, func(c CRIDLinkKnockV1SanitizationCase) string { return c.Name }); err != nil {
		return err
	}
	for _, c := range cases {
		fixture := fixtures[c.Name]
		if !cridLinkKnockV1JSONMatches(c.RedirectInfo, fixture) {
			return fmt.Errorf("conformance: CRID link knock sanitization case %q redirect_info does not match its fixture", c.Name)
		}
		if want := cridLinkKnockV1SanitizeRedirectInfo(c.RedirectInfo); !reflect.DeepEqual(c.Expected, want) {
			return fmt.Errorf("conformance: CRID link knock sanitization case %q expectation = %s, want %s", c.Name, cridLinkKnockV1Describe(c.Expected), cridLinkKnockV1Describe(want))
		}
	}
	return nil
}

// cridLinkKnockV1JSONMatches reports whether a committed JSON value equals a
// fixture value. Member order and whitespace are not significant here; the
// request suite compares canonical bytes separately.
func cridLinkKnockV1JSONMatches(raw json.RawMessage, want any) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var got any
	if err := dec.Decode(&got); err != nil {
		return false
	}
	return reflect.DeepEqual(got, want)
}

func cridLinkKnockV1Describe(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%+v", value)
	}
	return string(encoded)
}

// cridLinkKnockV1TruncateUserAgent keeps the longest prefix that fits the
// byte limit and ends on a code point boundary, so the result is valid UTF-8.
func cridLinkKnockV1TruncateUserAgent(userAgent string) string {
	if len(userAgent) <= CRIDLinkKnockV1UserAgentMaxBytes {
		return userAgent
	}
	cut := CRIDLinkKnockV1UserAgentMaxBytes
	for cut > 0 && !utf8.RuneStart(userAgent[cut]) {
		cut--
	}
	return userAgent[:cut]
}

// cridLinkKnockV1RequestExpectation is the reference request gate. It is the
// CRID v1 local gate plus one rule of this contract: the version byte must be
// one a client can verify an issued link against, which is an active row of
// the CRID v1 registry. The CRID v1 gate forwards an unregistered or reserved
// version. A link request for one would only fetch a link the client must
// then reject, so the request is refused, under the CRID v1 version class
// rather than a class of this artifact's own.
func cridLinkKnockV1RequestExpectation(crid string) (outcome, rejectClass string) {
	if outcome, rejectClass := deriveCRIDV1ValueExpectation(crid); outcome != ExpectAccept {
		return outcome, rejectClass
	}
	// The version derivation fails for a registered version in a form the
	// registry does not pin, so a row it names is the row for this shape.
	if versionHex, _, _, _, err := deriveCRIDV1VersionExpectation(crid); err == nil {
		for _, row := range cridV1VersionRegistry {
			if row.VersionHex == versionHex && row.Status == CRIDV1StatusActive {
				return ExpectAccept, ""
			}
		}
	}
	return ExpectReject, CRIDV1RejectVersion
}

type cridLinkKnockV1WireRequest struct {
	HeaderType    int                         `json:"headerType"`
	AuthServiceID string                      `json:"aspId"`
	ResourceID    string                      `json:"resId"`
	UserData      cridLinkKnockV1WireUserData `json:"usrData"`
}

type cridLinkKnockV1WireUserData struct {
	CRID      string `json:"qurl_crid"`
	UserAgent string `json:"qurl_user_agent,omitempty"`
}

// cridLinkKnockV1SerializeRequest is the reference request builder. It
// returns the canonical bytes and the user agent actually sent. The canonical
// form is what JavaScript's JSON.stringify emits for the body object; this
// stdlib encoder agrees with it for every string the gate below admits.
func cridLinkKnockV1SerializeRequest(input CRIDLinkKnockV1RequestInput) (serialized, sentUserAgent string, err error) {
	if outcome, rejectClass := cridLinkKnockV1RequestExpectation(input.CRID); outcome != ExpectAccept {
		return "", "", fmt.Errorf("CRID fails the request gate with class %q", rejectClass)
	}
	wire := cridLinkKnockV1WireRequest{
		HeaderType:    CRIDLinkKnockV1KnockHeaderType,
		AuthServiceID: CRIDLinkKnockV1AuthServiceID,
		ResourceID:    CRIDLinkKnockV1ResourceID,
		UserData:      cridLinkKnockV1WireUserData{CRID: input.CRID},
	}
	if input.UserAgent != nil {
		for _, r := range *input.UserAgent {
			// Go escapes control characters and U+2028/U+2029 differently
			// from JSON.stringify, and rewrites an invalid sequence, so a
			// fixture that used one would pin this encoder, not the contract.
			if r < 0x20 || r == 0x2028 || r == 0x2029 || r == utf8.RuneError {
				return "", "", fmt.Errorf("user agent contains %U, which this reference cannot serialize canonically", r)
			}
		}
		wire.UserData.UserAgent = cridLinkKnockV1TruncateUserAgent(*input.UserAgent)
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(wire); err != nil {
		return "", "", err
	}
	return strings.TrimSuffix(encoded.String(), "\n"), wire.UserData.UserAgent, nil
}

func cridLinkKnockV1JSONObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, false
	}
	return fields, true
}

// cridLinkKnockV1JSONString accepts only a JSON string. json.Unmarshal alone
// would also accept null and leave the destination empty.
func cridLinkKnockV1JSONString(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return "", false
	}
	return value, true
}

// cridLinkKnockV1SanitizeRedirectInfo is the reference display-metadata gate.
// It never fails: anything it cannot use is simply absent, and the publisher
// is unverified unless the value is the JSON boolean true.
func cridLinkKnockV1SanitizeRedirectInfo(raw json.RawMessage) CRIDLinkKnockV1LinkInfo {
	var info CRIDLinkKnockV1LinkInfo
	fields, ok := cridLinkKnockV1JSONObject(raw)
	if !ok {
		return info
	}
	info.QURLID, _ = cridLinkKnockV1JSONString(fields["qurl_id"])
	info.ExpiresAt, _ = cridLinkKnockV1JSONString(fields["expires_at"])
	info.ResourceCreatedAt, _ = cridLinkKnockV1JSONString(fields["resource_created_at"])
	publisher, ok := cridLinkKnockV1JSONObject(fields["publisher"])
	if !ok {
		return info
	}
	if name, ok := cridLinkKnockV1JSONString(publisher["name"]); ok && utf8.RuneCountInString(name) <= CRIDLinkKnockV1PublisherNameMaxCodePoints {
		info.Publisher.Name = name
	}
	info.Publisher.Verified = bytes.Equal(bytes.TrimSpace(publisher["verified"]), []byte("true"))
	return info
}

// cridLinkKnockV1InfoCRIDMatches is the one hard redirectInfo check: a crid
// member, when present, must be exactly the requested CRID string. Only an
// absent member passes; a number, a null or an object is present and unequal.
func cridLinkKnockV1InfoCRIDMatches(requestedCRID string, ack map[string]json.RawMessage) bool {
	info, ok := cridLinkKnockV1JSONObject(ack["redirectInfo"])
	if !ok {
		return true
	}
	raw, present := info["crid"]
	if !present {
		return true
	}
	echoed, ok := cridLinkKnockV1JSONString(raw)
	return ok && echoed == requestedCRID
}

// openLink runs the checks that need no requested CRID: link shape, transport
// framing and the issuer signature. It returns the reconstructed canonical
// fragment and the signed claims, or the first failing reject class.
func (env *cridLinkKnockV1Environment) openLink(redirect string) (string, cridLinkKnockV1LinkClaims, string) {
	var claims cridLinkKnockV1LinkClaims
	parsed, err := url.Parse(redirect)
	if err != nil || parsed.User != nil || parsed.Opaque != "" || parsed.Scheme+"://"+parsed.Host != CRIDLinkKnockV1LinkOrigin {
		return "", claims, CRIDLinkKnockV1RejectOrigin
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.ForceQuery {
		return "", claims, CRIDLinkKnockV1RejectPathOrQuery
	}
	// The fragment is taken verbatim: a transport decoder must see the exact
	// presented bytes, not a percent-decoded rendering of them.
	_, fragment, _ := strings.Cut(redirect, "#")
	canonical, err := decodeConformanceTransport(env.transportContract, fragment)
	if err != nil {
		return "", claims, CRIDLinkKnockV1RejectTransport
	}
	parts := strings.Split(canonical, ".")
	if len(parts) != 4 || !env.verifyIssuerSignature(parts[1], parts[3]) {
		return "", claims, CRIDLinkKnockV1RejectIssuerSignature
	}
	// The claims are read only now that their signature has verified. If they
	// cannot be read, no resource key is left to derive a CRID from, and the
	// next check reports that.
	if claimsJSON, err := strictRawBase64URL(parts[1]); err == nil {
		_ = json.Unmarshal(claimsJSON, &claims)
	}
	return canonical, claims, ""
}

// verifyIssuerSignature applies the qURL v2 issuer rule: a 64-byte raw r||s
// low-S P-256 signature over SHA-256(prefix || 0x00 || claims_b64).
func (env *cridLinkKnockV1Environment) verifyIssuerSignature(claimsB64, signatureB64 string) bool {
	raw, err := strictRawBase64URL(signatureB64)
	if err != nil || len(raw) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	order := elliptic.P256().Params().N
	if r.Sign() <= 0 || r.Cmp(order) >= 0 || s.Sign() <= 0 || s.Cmp(new(big.Int).Rsh(order, 1)) > 0 {
		return false
	}
	message := append(append([]byte(env.signingPrefix), 0), claimsB64...)
	digest := sha256.Sum256(message)
	return ecdsa.Verify(env.issuerPublic, digest[:], r, s)
}

// linkRejectClass is the reference client verification of a link-issued ACK.
// It returns the empty string when the link may be used for the requested
// CRID, and otherwise the first failing class in reference order.
func (env *cridLinkKnockV1Environment) linkRejectClass(requestedCRID string, ack map[string]json.RawMessage) string {
	redirect, ok := cridLinkKnockV1JSONString(ack["redirectUrl"])
	if !ok || redirect == "" {
		return CRIDLinkKnockV1RejectMissingRedirect
	}
	_, claims, rejectClass := env.openLink(redirect)
	if rejectClass != "" {
		return rejectClass
	}
	if outcome, err := CRIDV1KeyMatchExpectation(requestedCRID, claims.ResourcePublicKeyB64); err != nil || outcome != CRIDV1OutcomeMatch {
		return CRIDLinkKnockV1RejectCRIDMismatch
	}
	if !cridLinkKnockV1InfoCRIDMatches(requestedCRID, ack) {
		return CRIDLinkKnockV1RejectInfoCRIDMismatch
	}
	return ""
}

// interpretACK is the reference reply interpreter. A non-empty reject class
// means the reply was a link-issued ACK whose link must not be used; that is
// a hard error, not a client result.
func (env *cridLinkKnockV1Environment) interpretACK(requestedCRID string, body json.RawMessage) (CRIDLinkKnockV1ACKExpectation, string, error) {
	var result CRIDLinkKnockV1ACKExpectation
	ack, ok := cridLinkKnockV1JSONObject(body)
	if !ok {
		return result, "", errors.New("body is not a JSON object")
	}
	// The empty string, "0" and a missing errCode are the success codes of an
	// ordinary knock. A link request opens nothing, so none of them is a
	// usable answer, whatever else the body carries. Neither is an errCode
	// that is not a string: a client never coerces one into a code it knows.
	code, isString := cridLinkKnockV1JSONString(ack["errCode"])
	if !isString || code == "" || code == "0" {
		result.ClientResult = CRIDLinkKnockV1ResultProtocolViolation
		return result, "", nil
	}
	entry, known := cridLinkKnockV1ErrorCodes[code]
	if !known {
		result.ClientResult = CRIDLinkKnockV1ResultServerError
		return result, "", nil
	}
	result.ClientResult = entry.ClientResult
	if code != CRIDLinkKnockV1CodeLinkIssued {
		return result, "", nil
	}
	if rejectClass := env.linkRejectClass(requestedCRID, ack); rejectClass != "" {
		return CRIDLinkKnockV1ACKExpectation{}, rejectClass, nil
	}
	result.Link, _ = cridLinkKnockV1JSONString(ack["redirectUrl"])
	info := cridLinkKnockV1SanitizeRedirectInfo(ack["redirectInfo"])
	result.Info = &info
	return result, "", nil
}
