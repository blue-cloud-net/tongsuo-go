package ecdh_test

import (
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/ecdh"
	"testing"
)

// TestIndependentPublicLifecycle 验证相关操作的正确性、边界与错误处理。
//
// TestIndependentPublicLifecycle checks operation correctness, boundaries and error handling.
func TestIndependentPublicLifecycle(t *testing.T) {
	for _, alg := range []string{"P-256", "P-384", "P-521", "secp256k1", "X25519", "X448"} {
		t.Run(alg, func(t *testing.T) {
			var src asym.PrivateKey
			var err error
			switch alg {
			case "X25519":
				src, err = asym.GenerateX25519()
			case "X448":
				src, err = asym.GenerateX448()
			default:
				src, err = asym.GenerateEC(alg)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer asym.Close(src)
			key, err := ecdh.LoadPrivateKey(src)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Close()
			pub, err := key.Public()
			if err != nil {
				t.Fatal(err)
			}
			defer pub.Close()
			second, err := key.Public()
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if err := pub.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := key.MarshalPEM(); err != nil {
				t.Fatal("public closed private", err)
			}
			if err := asym.Close(src); err != nil {
				t.Fatal(err)
			}
			if err := key.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := second.MarshalPEM(); err != nil {
				t.Fatal("private closed public", err)
			}
			if _, err := key.Public(); err == nil {
				t.Fatal("closed Public accepted")
			}
			if _, err := key.MarshalPEM(); err == nil {
				t.Fatal("closed private accepted")
			}
			if key.Curve() != nil {
				t.Fatal("closed curve")
			}
		})
	}
	var priv *ecdh.PrivateKey
	var pub *ecdh.PublicKey
	for _, close := range []func() error{priv.Close, pub.Close, (&ecdh.PrivateKey{}).Close, (&ecdh.PublicKey{}).Close} {
		if err := close(); err != nil {
			t.Fatal(err)
		}
	}
}
