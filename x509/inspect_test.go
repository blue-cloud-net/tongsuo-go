package x509

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// buildEmailCert 构建一张带 rfc822Name SAN 的证书，供证书检查类用例复用。
//
// buildEmailCert builds a certificate carrying an rfc822Name SAN entry for the
// certificate inspection test cases.
func buildEmailCert(t *testing.T, serial int64) *Certificate {
	t.Helper()
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "mail.example.com")

	cert := NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(serial); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetIssuer(subject); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddSubjectAltName("email:admin@mail.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestSerialHex 验证序列号的大写十六进制形式，并与 int64 视图交叉校验。
//
// TestSerialHex verifies the uppercase hexadecimal form of the serial number and
// cross-checks it against the int64 view.
func TestSerialHex(t *testing.T) {
	cert := buildEmailCert(t, 0x1E971660AE8CEE19)
	t.Cleanup(func() { _ = cert.Close() })

	got := cert.SerialHex()
	if got == "" {
		t.Fatal("SerialHex() = \"\", want a hex string")
	}
	if got != strings.ToUpper(got) {
		t.Fatalf("SerialHex() = %q, want uppercase", got)
	}
	if strings.HasPrefix(got, "0x") || strings.HasPrefix(got, "serial=") {
		t.Fatalf("SerialHex() = %q, want bare hex without prefix", got)
	}
	// 能被 hex.DecodeString 解析
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("SerialHex() = %q is not hex: %v", got, err)
	}
	// 与 Serial() 的交叉校验（本例序列号在 int64 范围内）
	want := int64(0x1E971660AE8CEE19)
	if cert.Serial() != want {
		t.Fatalf("Serial() = %d, want %d", cert.Serial(), want)
	}
	if wantHex := strings.ToUpper(strconv.FormatUint(uint64(want), 16)); got != wantHex {
		t.Fatalf("SerialHex() = %q, want %q", got, wantHex)
	}

	// 小序列号不带多余前导零
	c2 := buildEmailCert(t, 42)
	t.Cleanup(func() { _ = c2.Close() })
	if got := c2.SerialHex(); got != "2A" {
		t.Fatalf("SerialHex(42) = %q, want 2A", got)
	}

	// 已关闭的证书返回空串
	_ = c2.Close()
	if got := c2.SerialHex(); got != "" {
		t.Fatalf("SerialHex() on closed cert = %q, want \"\"", got)
	}
}

// TestNameHash 验证 subject / issuer hash：自签证书两者相同，
// 且 subject 与 issuer 不同的证书两者不同。
//
// TestNameHash verifies the subject and issuer hashes: they are equal for a
// self-signed certificate and differ when subject and issuer differ.
func TestNameHash(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// 自签：subject == issuer
	selfName := NewName().Add("CN", "self-hash.example.com")
	selfCert, err := CreateCertificate(selfName, selfName, 1,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = selfCert.Close() })
	if selfCert.SubjectHash() != selfCert.IssuerHash() {
		t.Errorf("self-signed: SubjectHash() = %08x, IssuerHash() = %08x, want equal",
			selfCert.SubjectHash(), selfCert.IssuerHash())
	}

	// subject != issuer：两者必须不同
	caName := NewName().Add("CN", "ca-hash.example.com")
	leafName := NewName().Add("CN", "leaf-hash.example.com")
	leaf, err := CreateCertificate(leafName, caName, 2,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leaf.Close() })
	if leaf.SubjectHash() == leaf.IssuerHash() {
		t.Error("SubjectHash() should differ from IssuerHash() when names differ")
	}
	// 交换 subject / issuer 后 hash 必须随之互换（hash 覆盖全名字）
	swapped, err := CreateCertificate(caName, leafName, 3,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = swapped.Close() })
	if swapped.SubjectHash() != leaf.IssuerHash() {
		t.Error("SubjectHash of swapped cert should equal IssuerHash of the original")
	}

	// 已关闭的证书返回 0
	_ = leaf.Close()
	if got := leaf.SubjectHash(); got != 0 {
		t.Errorf("SubjectHash() on closed cert = %08x, want 0", got)
	}
	if got := leaf.IssuerHash(); got != 0 {
		t.Errorf("IssuerHash() on closed cert = %08x, want 0", got)
	}
}

// TestCheckEmail 验证 rfc822Name SAN 的邮箱匹配与三类失败路径。
//
// TestCheckEmail verifies rfc822Name SAN matching and the three failure paths.
func TestCheckEmail(t *testing.T) {
	cert := buildEmailCert(t, 7)
	t.Cleanup(func() { _ = cert.Close() })

	if err := cert.CheckEmail("admin@mail.example.com"); err != nil {
		t.Errorf("CheckEmail(match) = %v, want nil", err)
	}
	err := cert.CheckEmail("nobody@mail.example.com")
	if err == nil {
		t.Error("CheckEmail(no match) should fail")
	} else if !strings.Contains(err.Error(), "not valid for email") {
		t.Errorf("unexpected error: %v", err)
	}
	if err := cert.CheckEmail(""); err == nil {
		t.Error("CheckEmail(\"\") should fail")
	}

	// 已关闭的证书
	_ = cert.Close()
	if err := cert.CheckEmail("admin@mail.example.com"); err == nil {
		t.Error("CheckEmail on closed cert should fail")
	} else if !strings.Contains(err.Error(), "invalid certificate") {
		t.Errorf("unexpected error: %v", err)
	}
}
