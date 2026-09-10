package key_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/key"
)

func TestGenerateSymmetricKey(t *testing.T) {
	cases := []struct {
		alg  key.Algorithm
		size int
	}{
		{key.AlgAES128, 16},
		{key.AlgAES256, 32},
		{key.AlgSM4, 16},
	}
	for _, c := range cases {
		k, err := key.GenerateSymmetricKey(c.alg)
		if err != nil {
			t.Fatalf("GenerateSymmetricKey(%s): %v", c.alg, err)
		}
		if k.Algorithm() != c.alg {
			t.Errorf("Algorithm() = %s, want %s", k.Algorithm(), c.alg)
		}
		if k.Size() != c.size {
			t.Errorf("Size() = %d, want %d", k.Size(), c.size)
		}
		if len(k.Bytes()) != c.size {
			t.Errorf("len(Bytes()) = %d, want %d", len(k.Bytes()), c.size)
		}
	}
}

func TestGenerateSymmetricKeyUnknown(t *testing.T) {
	if _, err := key.GenerateSymmetricKey("FOO"); !errors.Is(err, key.ErrUnknownAlgorithm) {
		t.Fatalf("error = %v, want ErrUnknownAlgorithm", err)
	}
}

func TestNewAESKeyValidation(t *testing.T) {
	if _, err := key.NewAESKey(make([]byte, 15)); err == nil {
		t.Fatal("15-byte AES key: want error")
	}
	if _, err := key.NewAESKey(make([]byte, 17)); err == nil {
		t.Fatal("17-byte AES key: want error")
	}
	k, err := key.NewAESKey(make([]byte, 32))
	if err != nil {
		t.Fatalf("32-byte AES key: %v", err)
	}
	if k.Algorithm() != key.AlgAES256 {
		t.Errorf("Algorithm() = %s, want AES-256", k.Algorithm())
	}
}

func TestNewSM4KeyValidation(t *testing.T) {
	if _, err := key.NewSM4Key(make([]byte, 15)); err == nil {
		t.Fatal("15-byte SM4 key: want error")
	}
	if _, err := key.NewSM4Key(make([]byte, 17)); err == nil {
		t.Fatal("17-byte SM4 key: want error")
	}
}

func TestRoundTrip(t *testing.T) {
	algs := []key.Algorithm{key.AlgAES128, key.AlgAES256, key.AlgSM4}
	for _, alg := range algs {
		k, err := key.GenerateSymmetricKey(alg)
		if err != nil {
			t.Fatalf("GenerateSymmetricKey(%s): %v", alg, err)
		}
		pemBytes, err := k.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%s): %v", alg, err)
		}
		got, err := key.ParseSymmetricKey(pemBytes)
		if err != nil {
			t.Fatalf("ParseSymmetricKey(%s): %v", alg, err)
		}
		if got.Algorithm() != alg {
			t.Errorf("parsed Algorithm() = %s, want %s", got.Algorithm(), alg)
		}
		if !bytes.Equal(got.Bytes(), k.Bytes()) {
			t.Errorf("parsed bytes differ from original for %s", alg)
		}
		if !got.Equal(k) {
			t.Errorf("parsed key not Equal to original for %s", alg)
		}
	}
}

func TestBytesCopyIsolation(t *testing.T) {
	k, err := key.GenerateSymmetricKey(key.AlgAES256)
	if err != nil {
		t.Fatal(err)
	}
	b := k.Bytes()
	b[0] ^= 0xff
	if bytes.Equal(b, k.Bytes()) {
		t.Fatal("Bytes() must return an independent copy")
	}
}

func TestEqualNegative(t *testing.T) {
	a1, err := key.NewAESKey(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := key.NewAESKey(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if !a1.Equal(a2) {
		t.Error("two zero AES-128 keys should be equal")
	}
	s, err := key.NewSM4Key(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if a1.Equal(s) {
		t.Error("AES-128 zero key must not equal SM4 zero key")
	}
	if a1.Equal(nil) {
		t.Error("key must not be equal to nil")
	}
	mut := a2.Bytes()
	mut[0] = 0x01
	a3, err := key.NewAESKey(mut)
	if err != nil {
		t.Fatal(err)
	}
	if a1.Equal(a3) {
		t.Error("differing keys reported equal")
	}
}

func TestCloseSymmetric(t *testing.T) {
	k, err := key.GenerateSymmetricKey(key.AlgSM4)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Close(k); err != nil {
		t.Fatalf("Close(symmetric) = %v, want nil", err)
	}
	if err := key.Close(nil); err != nil {
		t.Fatalf("Close(nil) = %v, want nil", err)
	}
}

func TestParseSymmetricKeyErrors(t *testing.T) {
	if _, err := key.ParseSymmetricKey([]byte("not a pem")); err == nil {
		t.Fatal("garbage input: want error")
	}
	badType := []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
	if _, err := key.ParseSymmetricKey(badType); err == nil {
		t.Fatal("non-symmetric PEM type: want error")
	}
}
