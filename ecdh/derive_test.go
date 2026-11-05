package ecdh_test

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/ecdh"
)

// TestDirectDeriveSharedSecret 验证六条曲线的适配入口与现有路径相同，且不关闭源密钥。
//
// TestDirectDeriveSharedSecret checks all six curves against existing derivation without closing source keys.
func TestDirectDeriveSharedSecret(t *testing.T) {
	for _, curve := range ecdh.Curves() {
		t.Run(curve, func(t *testing.T) {
			generate := func() asym.PrivateKey {
				var key asym.PrivateKey
				var err error
				switch curve {
				case "X25519":
					key, err = asym.GenerateX25519()
				case "X448":
					key, err = asym.GenerateX448()
				default:
					key, err = asym.GenerateEC(curve)
				}
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { asym.Close(key) })
				return key
			}
			a, b := generate(), generate()
			x, err := ecdh.DeriveSharedSecret(a, b.Public())
			if err != nil {
				t.Fatal(err)
			}
			y, err := ecdh.DeriveSharedSecret(b, a.Public())
			if err != nil || !bytes.Equal(x, y) {
				t.Fatal("agreement", err)
			}
			priv, err := ecdh.LoadPrivateKey(a)
			if err != nil {
				t.Fatal(err)
			}
			defer priv.Close()
			pub, err := ecdh.LoadPublicKey(b.Public())
			if err != nil {
				t.Fatal(err)
			}
			defer pub.Close()
			want, err := ecdh.SharedSecret(priv, pub)
			if err != nil || !bytes.Equal(x, want) {
				t.Fatal("existing path", err)
			}
			if _, err = a.MarshalPrivateKeyPEM(); err != nil {
				t.Fatal("source closed", err)
			}
			asym.Close(a)
			if _, err = ecdh.DeriveSharedSecret(a, b.Public()); err == nil {
				t.Fatal("closed key")
			}
		})
	}
	a, _ := asym.GenerateEC("P-256")
	defer asym.Close(a)
	b, _ := asym.GenerateEC("P-384")
	defer asym.Close(b)
	if _, err := ecdh.DeriveSharedSecret(a, b.Public()); err == nil {
		t.Fatal("cross curve")
	}
	sm2, _ := asym.GenerateSM2()
	defer asym.Close(sm2)
	if _, err := ecdh.DeriveSharedSecret(sm2, sm2.Public()); !errors.Is(err, ecdh.ErrUnsupportedKey) {
		t.Fatal(err)
	}
	if _, err := ecdh.DeriveSharedSecret(nil, a.Public()); err == nil {
		t.Fatal("nil")
	}
}

// TestSM2DHAgreement 验证角色与 ID 对称性、输出长度、参数错误及句柄释放。
//
// TestSM2DHAgreement checks role/ID symmetry, output length, invalid arguments and handle ownership.
func TestSM2DHAgreement(t *testing.T) {
	generate := func() asym.PrivateKey {
		k, e := asym.GenerateSM2()
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { asym.Close(k) })
		return k
	}
	a, b, ra, rb := generate(), generate(), generate(), generate()
	alice := ecdh.SM2DHOptions{StaticKey: a, PeerStaticKey: b.Public(), EphemeralKey: ra, PeerEphemeralKey: rb.Public(), SelfID: []byte("Alice"), PeerID: []byte("Bob"), Role: ecdh.SM2DHInitiator, OutputLen: 32}
	bob := ecdh.SM2DHOptions{StaticKey: b, PeerStaticKey: a.Public(), EphemeralKey: rb, PeerEphemeralKey: ra.Public(), SelfID: []byte("Bob"), PeerID: []byte("Alice"), Role: ecdh.SM2DHResponder, OutputLen: 32}
	x, err := ecdh.DeriveSM2DH(&alice)
	if err != nil {
		t.Fatal(err)
	}
	y, err := ecdh.DeriveSM2DH(&bob)
	if err != nil || !bytes.Equal(x, y) || len(x) != 32 {
		t.Fatalf("agreement x=%x y=%x: %v", x, y, err)
	}
	for _, size := range []int{1, 16, 33, 64} {
		alice.OutputLen = size
		bob.OutputLen = size
		x, err = ecdh.DeriveSM2DH(&alice)
		if err != nil {
			t.Fatal(err)
		}
		y, err = ecdh.DeriveSM2DH(&bob)
		if err != nil || !bytes.Equal(x, y) || len(x) != size {
			t.Fatal("length", err)
		}
	}
	alice.OutputLen = 32
	bob.OutputLen = 32
	bob.SelfID = []byte("Mallory")
	y, err = ecdh.DeriveSM2DH(&bob)
	if err != nil {
		t.Fatal(err)
	}
	x, err = ecdh.DeriveSM2DH(&alice)
	if err != nil || bytes.Equal(x, y) {
		t.Fatal("ID not bound", err)
	}
	bob.SelfID = []byte("Bob")
	bob.Role = ecdh.SM2DHInitiator
	y, err = ecdh.DeriveSM2DH(&bob)
	if err != nil || bytes.Equal(x, y) {
		t.Fatal("role not bound", err)
	}
	for _, mutate := range []func(*ecdh.SM2DHOptions){func(o *ecdh.SM2DHOptions) { o.OutputLen = 0 }, func(o *ecdh.SM2DHOptions) { o.Role = 0 }, func(o *ecdh.SM2DHOptions) { o.SelfID = nil }, func(o *ecdh.SM2DHOptions) { o.PeerID = make([]byte, 8192) }, func(o *ecdh.SM2DHOptions) { o.StaticKey = nil }, func(o *ecdh.SM2DHOptions) { o.PeerEphemeralKey = nil }} {
		bad := alice
		mutate(&bad)
		if _, e := ecdh.DeriveSM2DH(&bad); e == nil {
			t.Fatal("invalid options")
		}
	}
	if _, err = ecdh.DeriveSM2DH(nil); err == nil {
		t.Fatal("nil options")
	}
	if _, err = a.MarshalPrivateKeyPEM(); err != nil {
		t.Fatal("source closed", err)
	}
	asym.Close(ra)
	if _, err = ecdh.DeriveSM2DH(&alice); err == nil {
		t.Fatal("closed ephemeral")
	}
}

// TestSM2DHFixedVector 验证 GB/T 32918.5-2017 附录 B.2 的标准 SM2 曲线示例。
// 数据对照：https://github.com/ww-rm/gmalg/blob/main/tests.py 的 test_keyxchg2。
//
// TestSM2DHFixedVector checks GB/T 32918.5-2017 appendix B.2 on the standard SM2 curve.
// Data reference: test_keyxchg2 at https://github.com/ww-rm/gmalg/blob/main/tests.py.
func TestSM2DHFixedVector(t *testing.T) {
	load := func(s string) asym.PrivateKey {
		scalar, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		der, e := asn1.Marshal(struct {
			Version    int
			PrivateKey []byte
			Curve      asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
		}{1, scalar, asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}})
		if e != nil {
			t.Fatal(e)
		}
		key, e := asym.LoadPrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { asym.Close(key) })
		return key
	}
	a := load("81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029")
	b := load("785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5")
	ra := load("D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3")
	rb := load("7E07124814B309489125EAED101113164EBF0F3458C5BD88335C1F9D596243D6")
	alice := ecdh.SM2DHOptions{StaticKey: a, PeerStaticKey: b.Public(), EphemeralKey: ra, PeerEphemeralKey: rb.Public(), SelfID: []byte("1234567812345678"), PeerID: []byte("1234567812345678"), Role: ecdh.SM2DHInitiator, OutputLen: 16}
	bob := ecdh.SM2DHOptions{StaticKey: b, PeerStaticKey: a.Public(), EphemeralKey: rb, PeerEphemeralKey: ra.Public(), SelfID: alice.PeerID, PeerID: alice.SelfID, Role: ecdh.SM2DHResponder, OutputLen: 16}
	want, _ := hex.DecodeString("6C89347354DE2484C60B4AB1FDE4C6E5")
	for _, opts := range []*ecdh.SM2DHOptions{&alice, &bob} {
		got, e := ecdh.DeriveSM2DH(opts)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatalf("SM2DH vector: %x != %x: %v", got, want, e)
		}
	}
}
