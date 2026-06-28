package conformance

import (
	"embed"
	"fmt"
)

//go:embed vectors/qv2_conformance_vectors.json vectors/issuer_signature_vectors.json
var vectorsFS embed.FS

const (
	conformanceVectorsName = "vectors/qv2_conformance_vectors.json"
	issuerSignatureName    = "vectors/issuer_signature_vectors.json"
)

// QV2Vectors returns the raw bytes of the embedded qURL v2 conformance vectors
// (qv2_conformance_vectors.json). The bytes are the canonical wire-truth; a
// consumer that prefers to drive its own strict parser can feed these directly.
func QV2Vectors() []byte {
	b, err := vectorsFS.ReadFile(conformanceVectorsName)
	if err != nil {
		// Unreachable: the file is embedded at build time.
		panic(fmt.Sprintf("conformance: embedded %s missing: %v", conformanceVectorsName, err))
	}
	return b
}

// IssuerSignatureVectors returns the raw bytes of the embedded issuer-signature
// golden vectors (issuer_signature_vectors.json), which the signature class
// composes by reference.
func IssuerSignatureVectors() []byte {
	b, err := vectorsFS.ReadFile(issuerSignatureName)
	if err != nil {
		// Unreachable: the file is embedded at build time.
		panic(fmt.Sprintf("conformance: embedded %s missing: %v", issuerSignatureName, err))
	}
	return b
}

// Open returns the raw bytes of an embedded vectors file by its base name (for
// example "qv2_conformance_vectors.json" or "issuer_signature_vectors.json"), or
// by its full "vectors/..." path. It returns an error for any other name.
func Open(name string) ([]byte, error) {
	switch name {
	case conformanceVectorsName, "qv2_conformance_vectors.json":
		return vectorsFS.ReadFile(conformanceVectorsName)
	case issuerSignatureName, "issuer_signature_vectors.json":
		return vectorsFS.ReadFile(issuerSignatureName)
	default:
		return nil, fmt.Errorf("conformance: unknown embedded file %q", name)
	}
}

// ConformanceVectors strictly parses the embedded qURL v2 conformance artifact
// into a typed document, returning an error if it is malformed or is not the
// expected artifact.
func ConformanceVectors() (*ConformanceFile, error) {
	return ParseConformanceFile(QV2Vectors())
}

// SignatureVectors strictly parses the embedded issuer-signature vector file into
// a typed document, returning an error if it is malformed.
func SignatureVectors() (*VectorFile, error) {
	return ParseVectorFile(IssuerSignatureVectors())
}
