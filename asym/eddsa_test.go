package asym

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// TestEdDSAInstanceRFC8032 验证 RFC 8032 上下文/ph 标准向量及实例隔离。
//
// TestEdDSAInstanceRFC8032 checks RFC 8032 context/ph vectors and instance isolation.
func TestEdDSAInstanceRFC8032(t *testing.T) {
	data, err := os.ReadFile("testdata/rfc8032-instances.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Instance                    string
			SecretKey                   string `json:"secret_key"`
			PublicKey                   string `json:"public_key"`
			Message, Context, Signature string
		}
	}
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) < 8 {
		t.Fatal("missing RFC vectors")
	}
	for i, v := range vectors.Cases {
		decode := func(s string) []byte {
			b, e := hex.DecodeString(s)
			if e != nil {
				t.Fatal(e)
			}
			return b
		}
		alg := AlgEd25519
		if v.Instance == "Ed448" || v.Instance == "Ed448ph" {
			alg = AlgEd448
		}
		key, e := GenerateKeyFromSeed(alg, decode(v.SecretKey))
		if e != nil {
			t.Fatal(e)
		}
		defer Close(key)
		pub, e := RawPublicKey(key.Public())
		if e != nil || !bytes.Equal(pub, decode(v.PublicKey)) {
			t.Fatalf("vector %d public key: %v", i, e)
		}
		msg, context, want := decode(v.Message), decode(v.Context), decode(v.Signature)
		var sign func(PrivateKey, []byte, []byte) ([]byte, error)
		var verify func(PublicKey, []byte, []byte, []byte) error
		switch v.Instance {
		case "Ed25519ctx":
			sign, verify = SignEd25519ctx, VerifyEd25519ctx
		case "Ed25519ph":
			sign, verify = SignEd25519ph, VerifyEd25519ph
		case "Ed448":
			sign, verify = SignEd448WithContext, VerifyEd448WithContext
		case "Ed448ph":
			sign, verify = SignEd448ph, VerifyEd448ph
		default:
			t.Fatal(v.Instance)
		}
		supported, e := SupportsEdDSAInstance(key, v.Instance, context)
		if e != nil {
			t.Fatal(e)
		}
		got, e := sign(key, msg, context)
		if !supported {
			if meta.VersionNum() >= 0x30500000 {
				t.Fatalf("8.5 baseline missing %s: %v", v.Instance, e)
			}
			if !errors.Is(e, ErrUnsupported) {
				t.Fatal(e)
			}
			if e = verify(key.Public(), msg, want, context); !errors.Is(e, ErrUnsupported) {
				t.Fatal(e)
			}
			continue
		}
		if e != nil || !bytes.Equal(got, want) {
			t.Fatalf("vector %d %s: got %x want %x: %v", i, v.Instance, got, want, e)
		}
		if e = verify(key.Public(), msg, want, context); e != nil {
			t.Fatal(e)
		}
		if e = verify(key.Public(), append(msg, 1), want, context); !errors.Is(e, ErrSignature) {
			t.Fatalf("tamper %v", e)
		}
		if e = verify(key.Public(), msg, want, append(context, 1)); !errors.Is(e, ErrSignature) {
			t.Fatalf("context mismatch %v", e)
		}
		bad := append([]byte(nil), want...)
		bad[0] ^= 1
		if e = verify(key.Public(), msg, bad, context); !errors.Is(e, ErrSignature) {
			t.Fatalf("signature mismatch %v", e)
		}
	}
}

// TestEdDSAInstanceBoundaries 验证上下文边界、密钥错配、空消息及关闭后调用。
//
// TestEdDSAInstanceBoundaries checks context limits, key mismatch, empty messages and closed keys.
func TestEdDSAInstanceBoundaries(t *testing.T) {
	key, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	defer Close(key)
	if _, err = SignEd25519ctx(key, nil, nil); err == nil {
		t.Fatal("empty ctx")
	}
	if _, err = SignEd25519ph(key, nil, make([]byte, 256)); err == nil {
		t.Fatal("long context")
	}
	if _, err = SignEd448ph(key, nil, nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	if _, err = SignEd25519ph(nil, nil, nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	if _, err = SupportsEdDSAInstance(key, "unknown", nil); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Fatal(err)
	}
	if ok, e := SupportsEdDSAInstance(key, "Ed25519ph", nil); e != nil {
		t.Fatal(e)
	} else if ok {
		for _, ctx := range [][]byte{nil, make([]byte, 255)} {
			sig, e := SignEd25519ph(key, nil, ctx)
			if e != nil {
				t.Fatal(e)
			}
			if e = VerifyEd25519ph(key.Public(), nil, sig, ctx); e != nil {
				t.Fatal(e)
			}
			if e = VerifyEd25519ph(key.Public(), nil, sig[:63], ctx); !errors.Is(e, ErrSignature) {
				t.Fatal(e)
			}
			if e = VerifyEd25519(key.Public(), nil, sig); e == nil {
				t.Fatal("pure accepted ph signature")
			}
		}
	}
	Close(key)
	if _, err = SignEd25519ph(key, nil, nil); err == nil {
		t.Fatal("closed key")
	}
	if _, err = SupportsEdDSAInstance(key, "Ed25519ph", nil); err == nil {
		t.Fatal("closed probe")
	}
}
