package rsa

import (
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
)

// TestPrivateRoundtrip 验证私钥 XML 往返。
func TestPrivateRoundtrip(t *testing.T) {
	priv, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, tag := range []string{"RSAKeyValue", "Modulus", "Exponent", "D", "P", "Q", "DP", "DQ", "InverseQ"} {
		if !strings.Contains(s, "<"+tag+">") {
			t.Fatalf("XML missing %q: %s", tag, s)
		}
	}
	loaded, err := UnmarshalPrivate(data)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Key().Equal(priv.Key()) {
		t.Fatal("private XML roundtrip key mismatch")
	}
}

// TestPublicRoundtrip 验证公钥 XML 往返（仅 Modulus/Exponent）。
func TestPublicRoundtrip(t *testing.T) {
	priv, _ := rsa.GenerateKey(2048)
	pub := priv.Public()
	data, err := MarshalPublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "<Modulus>") || !strings.Contains(s, "<Exponent>") {
		t.Fatalf("XML missing public fields: %s", s)
	}
	if strings.Contains(s, "<D>") {
		t.Fatalf("public XML should not contain D: %s", s)
	}
	loaded, err := UnmarshalPublic(data)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Key().PublicEqual(pub.Key()) {
		t.Fatal("public XML roundtrip key mismatch")
	}
}

// TestPrivateFromPublicXML 验证私钥解析含 P/Q，公钥解析无 P/Q。
func TestPrivateFromPublicXML(t *testing.T) {
	priv, _ := rsa.GenerateKey(2048)
	_, _ = MarshalPrivate(priv)
	pubXML, _ := MarshalPublic(priv.Public())

	loadedPub, err := UnmarshalPublic(pubXML)
	if err != nil {
		t.Fatal(err)
	}
	if !loadedPub.Key().PublicEqual(priv.Public().Key()) {
		t.Fatal("public key mismatch")
	}

	// 用公钥 XML（无 D）尝试解析私钥应失败
	if _, err := UnmarshalPrivate(pubXML); err == nil {
		t.Fatal("unmarshal private from public XML should fail")
	}
}
