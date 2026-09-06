// Package genkit contains the dependency-free parts of the one-shot qv2
// vector generator. CI tests this package without compiling qurl-go, so the
// conformance repository never depends on a consumer SDK to validate its own
// published contract.
package genkit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

type TransportFieldContract struct {
	MaxEncodedLength int `json:"max_encoded_length"`
	MaxChunks        int `json:"max_chunks"`
}

type TransportEncodingContract struct {
	ComponentMax       int `json:"component_max"`
	MaxTransportLength int `json:"max_transport_length"`
	Fields             struct {
		Claims    TransportFieldContract `json:"claims"`
		Secret    TransportFieldContract `json:"secret"`
		Signature TransportFieldContract `json:"signature"`
	} `json:"fields"`
}

func EncodeTransportFragment(fragment string, contract TransportEncodingContract) (string, error) {
	if contract.ComponentMax <= 0 || contract.MaxTransportLength <= 0 {
		return "", fmt.Errorf("transport size bounds must be positive")
	}
	parts := strings.Split(fragment, ".")
	if len(parts) != 4 || parts[0] != "qv2" {
		return "", fmt.Errorf("canonical fragment has invalid shape")
	}
	fields := []struct {
		name   string
		value  string
		limits TransportFieldContract
	}{
		{name: "claims", value: parts[1], limits: contract.Fields.Claims},
		{name: "secret", value: parts[2], limits: contract.Fields.Secret},
		{name: "signature", value: parts[3], limits: contract.Fields.Signature},
	}
	counts := make([]string, 0, 3)
	chunks := make([]string, 0)
	for _, field := range fields {
		if field.limits.MaxEncodedLength <= 0 || field.limits.MaxChunks <= 0 {
			return "", fmt.Errorf("transport %s bounds must be positive", field.name)
		}
		if len(field.value) > field.limits.MaxEncodedLength {
			return "", fmt.Errorf("transport %s exceeds max_encoded_length", field.name)
		}
		fieldChunks := make([]string, 0, (len(field.value)+contract.ComponentMax-1)/contract.ComponentMax)
		for len(field.value) > contract.ComponentMax {
			fieldChunks = append(fieldChunks, field.value[:contract.ComponentMax])
			field.value = field.value[contract.ComponentMax:]
		}
		if field.value == "" {
			return "", fmt.Errorf("canonical fragment has empty field")
		}
		fieldChunks = append(fieldChunks, field.value)
		if len(fieldChunks) > field.limits.MaxChunks {
			return "", fmt.Errorf("transport %s exceeds max_chunks", field.name)
		}
		counts = append(counts, fmt.Sprint(len(fieldChunks)))
		chunks = append(chunks, fieldChunks...)
	}
	transport := "qv2t1." + strings.Join(append(counts, chunks...), ".")
	if len(transport) > contract.MaxTransportLength {
		return "", fmt.Errorf("transport fragment exceeds max_transport_length")
	}
	return transport, nil
}

func ReplaceExactJSONString(data []byte, oldValue, newValue string, wantCount int) ([]byte, error) {
	oldJSON, err := marshalJSONString(oldValue)
	if err != nil {
		return nil, err
	}
	newJSON, err := marshalJSONString(newValue)
	if err != nil {
		return nil, err
	}
	if got := bytes.Count(data, oldJSON); got != wantCount {
		return nil, fmt.Errorf("JSON string replacement found %d copies, want %d", got, wantCount)
	}
	return bytes.ReplaceAll(data, oldJSON, newJSON), nil
}

func marshalJSONString(value string) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}

// FixedP256PrivateKey returns a public, vector-only key. Stable key material
// keeps a claims-only edit from also rotating the issuer and resource public
// keys. The committed signatures remain non-reproducible because ECDSA uses a
// random nonce.
func FixedP256PrivateKey(fill byte) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()
	scalarBytes := bytes.Repeat([]byte{fill}, 32)
	d := new(big.Int).SetBytes(scalarBytes)
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, fmt.Errorf("fixed P-256 scalar is out of range")
	}
	x, y := curve.ScalarBaseMult(scalarBytes)
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}, nil
}

// FixedX25519PrivateKey returns a public, vector-only scalar in canonical
// clamped form. Returning already-clamped bytes makes clamping idempotent for
// consumers that parse, export, or use a raw scalar-multiplication API.
func FixedX25519PrivateKey(fill byte) []byte {
	privateKey := bytes.Repeat([]byte{fill}, 32)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64
	return privateKey
}
