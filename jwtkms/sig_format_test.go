package jwtkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestECDSASignerSigFormatter_RoundTrip(t *testing.T) {
	curves := []struct {
		name      string
		curve     elliptic.Curve
		keySize   int
		curveBits int
	}{
		{"P256", elliptic.P256(), 32, 256},
		{"P384", elliptic.P384(), 48, 384},
		{"P521", elliptic.P521(), 66, 521},
	}

	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			signer := ecdsaSignerSigFormatter(c.curveBits)
			verifier := ecdsaVerificationSigFormatter(c.keySize)

			priv, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}

			for i := 0; i < 50; i++ {
				digest := make([]byte, c.keySize)
				if _, err := rand.Read(digest); err != nil {
					t.Fatalf("rand read: %v", err)
				}

				derSig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
				if err != nil {
					t.Fatalf("sign asn1: %v", err)
				}

				// DER -> R||S
				rs, err := signer(derSig)
				if err != nil {
					t.Fatalf("signer formatter: %v", err)
				}
				if got, want := len(rs), 2*c.keySize; got != want {
					t.Fatalf("R||S length mismatch: got %d want %d", got, want)
				}

				// R||S -> DER
				roundTripped, err := verifier(rs)
				if err != nil {
					t.Fatalf("verifier formatter: %v", err)
				}

				// The resulting DER must verify with the same key/digest.
				if !ecdsa.VerifyASN1(&priv.PublicKey, digest, roundTripped) {
					t.Fatalf("verification of round-tripped signature failed")
				}
			}
		})
	}
}

func TestECDSAVerificationSigFormatter_HandlesShortRS(t *testing.T) {
	// R/S that are smaller than keySize should still produce a parseable DER (big-endian unsigned).
	keySize := 32
	formatter := ecdsaVerificationSigFormatter(keySize)

	rs := make([]byte, 2*keySize)
	rs[keySize-1] = 1 // R = 1
	rs[2*keySize-1] = 2 // S = 2

	der, err := formatter(rs)
	if err != nil {
		t.Fatalf("formatter: %v", err)
	}

	var parsed struct {
		R *big.Int
		S *big.Int
	}
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatalf("unmarshal der: %v", err)
	}
	if parsed.R.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("R: got %v want 1", parsed.R)
	}
	if parsed.S.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("S: got %v want 2", parsed.S)
	}
}

func TestECDSASignerSigFormatter_RejectsMalformedDER(t *testing.T) {
	formatter := ecdsaSignerSigFormatter(256)

	cases := [][]byte{
		nil,
		{},
		{0x00},
		{0x30, 0x00},         // DER sequence with zero length, missing R/S
		[]byte("not der at all"),
		bytes(0x30, 0xff, 0x01, 0x02), // sequence with bogus length
	}
	for i, c := range cases {
		if _, err := formatter(c); err == nil {
			t.Errorf("case %d: expected error for malformed DER %x", i, c)
		}
	}
}

func bytes(b ...byte) []byte { return b }

// TestECDSASignerSigFormatter_OversizedRSDoesNotPanic guards against the
// regression originally surfaced by FuzzECDSAFormatterRoundTrip: an attacker-
// controlled DER signature with R or S larger than the curve's expected byte
// length used to panic with a slice-bounds-out-of-range error. It must now
// return a clean error.
func TestECDSASignerSigFormatter_OversizedRSDoesNotPanic(t *testing.T) {
	signer := ecdsaSignerSigFormatter(256) // P256, expects 32 bytes per component

	// DER: SEQUENCE { INTEGER (33 bytes of 0x30), INTEGER (32 bytes of 0x30) }
	derSig := []byte{0x30, 0x46, 0x02, 0x21}
	derSig = append(derSig, mkBytes(0x30, 33)...)
	derSig = append(derSig, 0x02, 0x20)
	derSig = append(derSig, mkBytes(0x30, 32)...)

	if _, err := signer(derSig); err == nil {
		t.Fatal("expected error for oversized R, got nil")
	}
}

func mkBytes(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// FuzzECDSAFormatterRoundTrip fuzzes DER -> R||S -> DER. The signer formatter
// is given untrusted bytes (as if from KMS) and we ensure no panic, and that
// any successful round-trip preserves the encoded R and S exactly.
func FuzzECDSAFormatterRoundTrip(f *testing.F) {
	// Seed with a valid signature.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	digest := make([]byte, 32)
	for i := 0; i < 4; i++ {
		_, _ = rand.Read(digest)
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(sig)
	}

	signer := ecdsaSignerSigFormatter(256)
	verifier := ecdsaVerificationSigFormatter(32)

	f.Fuzz(func(t *testing.T, derSig []byte) {
		rs, err := signer(derSig)
		if err != nil {
			return
		}
		if len(rs) != 64 {
			t.Fatalf("R||S length: got %d want 64", len(rs))
		}
		// Now go back through the verifier formatter; must not panic and must
		// re-parse to the same R/S.
		back, err := verifier(rs)
		if err != nil {
			t.Fatalf("verifier roundtrip: %v", err)
		}
		var orig, rt struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(derSig, &orig); err != nil {
			return // signer happened to accept something asn1 won't re-parse here; not our concern
		}
		if _, err := asn1.Unmarshal(back, &rt); err != nil {
			t.Fatalf("unmarshal roundtrip: %v", err)
		}
		if orig.R.Cmp(rt.R) != 0 || orig.S.Cmp(rt.S) != 0 {
			t.Fatalf("R/S not preserved across round-trip: orig=(%v,%v) rt=(%v,%v)", orig.R, orig.S, rt.R, rt.S)
		}
	})
}
