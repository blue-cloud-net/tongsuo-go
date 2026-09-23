package rsa

import (
	"math/big"
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
)

// extractTag 提取 <Tag>value</Tag> 中的 base64 解码值（测试 helper）。未找到返回空串。
func extractTag(s, tag string) string {
	start := "<" + tag + ">"
	end := "</" + tag + ">"
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	j := strings.Index(s[i+len(start):], end)
	if j < 0 {
		return ""
	}
	return s[i+len(start) : i+len(start)+j]
}

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
	// CRT 字段值断言：DP/DQ/InverseQ 应等于 core.KeyParams 的 Dmp1/Dmq1/Iqmp
	// （即 XML 与本库 Params() 一致），保证不再走"重复 Mod/ModInverse"路径。
	lp := priv.Params()
	if lp == nil || lp.Dmp1 == nil || lp.Dmq1 == nil || lp.Iqmp == nil {
		t.Fatal("underlying CRT params should be populated")
	}
	dpXML := extractTag(s, "DP")
	dqXML := extractTag(s, "DQ")
	iqXML := extractTag(s, "InverseQ")
	if dpXML != b64Std(lp.Dmp1) {
		t.Fatalf("DP mismatch: got %s want %s", dpXML, b64Std(lp.Dmp1))
	}
	if dqXML != b64Std(lp.Dmq1) {
		t.Fatalf("DQ mismatch: got %s want %s", dqXML, b64Std(lp.Dmq1))
	}
	if iqXML != b64Std(lp.Iqmp) {
		t.Fatalf("InverseQ mismatch: got %s want %s", iqXML, b64Std(lp.Iqmp))
	}
	// 反向：DP/DQ/InverseQ 满足 Iqmp*Q ≡ 1 (mod P)
	qiq := new(big.Int).Mul(lp.Iqmp, lp.Q)
	one := big.NewInt(1)
	if qiq.Mod(qiq, lp.P).Cmp(one) != 0 {
		t.Fatal("InverseQ*Q mod P != 1")
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
