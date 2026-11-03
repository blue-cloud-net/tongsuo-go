package ecdh

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// TestParameters 验证命名/显式参数的读写与参数驱动生成。
//
// TestParameters checks named/explicit parameter round trips and parameter-based generation.
func TestParameters(t *testing.T) {
	for _, c := range []*Curve{P256(), P384(), P521(), Secp256k1()} {
		for _, explicit := range []bool{false, true} {
			data, err := MarshalParametersPEM(c, explicit)
			if err != nil {
				t.Fatal(err)
			}
			got, err := LoadParametersPEM(data)
			if err != nil || got.Name() != c.Name() {
				t.Fatalf("%s explicit=%v: %v %v", c.Name(), explicit, got, err)
			}
			key, err := GenerateKeyFromParameters(data)
			if err != nil {
				t.Fatal(err)
			}
			if err = asym.Check(key); err != nil {
				t.Fatal(err)
			}
			asym.Close(key)
			file := filepath.Join(t.TempDir(), "params.pem")
			if err = os.WriteFile(file, data, 0600); err != nil {
				t.Fatal(err)
			}
			got, err = LoadParametersFile(file)
			if err != nil || got.Name() != c.Name() {
				t.Fatalf("file: %v", err)
			}
		}
	}
	for _, c := range []*Curve{nil, X25519(), X448()} {
		if _, err := MarshalParametersPEM(c, false); err == nil {
			t.Fatal("accepted unsupported curve")
		}
	}
	if _, err := LoadParametersPEM([]byte("broken")); err == nil {
		t.Fatal("accepted malformed parameters")
	}
	if _, err := LoadParametersFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}
