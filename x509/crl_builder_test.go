package x509_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// crlAlgorithms 返回 CRL 签发用例覆盖的算法集合。
//
// crlAlgorithms returns the algorithm set covered by the CRL signing tests.
func crlAlgorithms() map[string]func() (asym.PrivateKey, error) {
	return map[string]func() (asym.PrivateKey, error){
		"SM2":     func() (asym.PrivateKey, error) { return asym.GenerateSM2() },
		"RSA":     func() (asym.PrivateKey, error) { return asym.GenerateRSA(2048) },
		"EC":      func() (asym.PrivateKey, error) { return asym.GenerateEC(asym.CurveP256) },
		"Ed25519": func() (asym.PrivateKey, error) { return asym.GenerateEd25519() },
		"Ed448":   func() (asym.PrivateKey, error) { return asym.GenerateEd448() },
	}
}

// mustCloseAsym 释放 asym 密钥，失败即终止。
//
// mustCloseAsym releases an asym key, failing the test on error.
func mustCloseAsym(t *testing.T, k asym.Key) {
	t.Helper()
	if err := asym.Close(k); err != nil {
		t.Errorf("asym.Close: %v", err)
	}
}

// caPair 表示一张自签 CA 证书与其私钥。
//
// caPair is a self-signed CA certificate together with its private key.
type caPair struct {
	cert *x509.Certificate
	priv asym.PrivateKey
}

// newCA 生成指定算法、指定有效期的自签 CA 证书（带 basicConstraints CA:TRUE
// 与 SKID / AKID，可作信任锚使用）。
//
// newCA builds a self-signed CA certificate with the given algorithm and
// validity window, carrying basicConstraints CA:TRUE plus SKID / AKID so it
// can serve as a trust anchor.
func newCA(t *testing.T, cn string, gen func() (asym.PrivateKey, error),
	notBefore, notAfter time.Time) caPair {
	t.Helper()
	priv, err := gen()
	if err != nil {
		t.Fatalf("generate %s: %v", cn, err)
	}
	subject := x509.NewName().Add("CN", cn).Add("O", "tongsuo-go")
	cert := x509.NewCertificate()
	if err := cert.SetSubject(subject); err != nil {
		t.Fatalf("SetSubject(%s): %v", cn, err)
	}
	if err := cert.SetIssuer(subject); err != nil {
		t.Fatalf("SetIssuer(%s): %v", cn, err)
	}
	if err := cert.SetVersion(2); err != nil {
		t.Fatalf("SetVersion(%s): %v", cn, err)
	}
	if err := cert.SetSerial(1); err != nil {
		t.Fatalf("SetSerial(%s): %v", cn, err)
	}
	if err := cert.SetValidity(notBefore, notAfter); err != nil {
		t.Fatalf("SetValidity(%s): %v", cn, err)
	}
	if err := cert.SetPublicKey(priv.Public()); err != nil {
		t.Fatalf("SetPublicKey(%s): %v", cn, err)
	}
	if err := cert.AddBasicConstraints(true); err != nil {
		t.Fatalf("AddBasicConstraints(%s): %v", cn, err)
	}
	if err := cert.AddSubjectKeyID(); err != nil {
		t.Fatalf("AddSubjectKeyID(%s): %v", cn, err)
	}
	if err := cert.AddAuthorityKeyID(cert); err != nil {
		t.Fatalf("AddAuthorityKeyID(%s): %v", cn, err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatalf("Sign(%s): %v", cn, err)
	}
	return caPair{cert: cert, priv: priv}
}

// newLeaf 用 ca 签发一张叶证书。
//
// newLeaf issues a leaf certificate from ca.
func newLeaf(t *testing.T, cn string, serial int64, ca caPair,
	notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	leafPriv, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	defer mustCloseAsym(t, leafPriv)
	subject := x509.NewName().Add("CN", cn).Add("O", "tongsuo-go")
	leaf, err := x509.CreateCertificate(subject, ca.cert.SubjectName(), serial,
		notBefore, notAfter, leafPriv.Public(), ca.priv)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", cn, err)
	}
	return leaf
}

// TestCRLBuilderFullFlow 验证构建器的完整语义：CRL Number / 时间窗 / 吊销条目
// （含原因码）/ AKID / 签发者、签名可验证、RevocationCheck 能命中、PEM 与 DER
// 往返后条目一致，以及 Sign 之后构建器失效、再次 Sign 报错。
//
// TestCRLBuilderFullFlow verifies the full builder semantics: CRL Number,
// validity window, revocation entries (with reason codes), AKID and issuer,
// a verifiable signature, RevocationCheck hitting the revoked certificates,
// identical entries after PEM and DER round trips, and the builder expiring
// after Sign (a second Sign must fail).
func TestCRLBuilderFullFlow(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	ca := newCA(t, "CRL Builder CA", func() (asym.PrivateKey, error) {
		return asym.GenerateSM2()
	}, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	defer func() { _ = ca.cert.Close() }()
	defer mustCloseAsym(t, ca.priv)

	revoked1 := newLeaf(t, "revoked-1.example", 1001, ca,
		now.Add(-time.Hour), now.Add(24*time.Hour))
	defer func() { _ = revoked1.Close() }()
	revoked2 := newLeaf(t, "revoked-2.example", 1002, ca,
		now.Add(-time.Hour), now.Add(24*time.Hour))
	defer func() { _ = revoked2.Close() }()
	alive := newLeaf(t, "alive.example", 1003, ca,
		now.Add(-time.Hour), now.Add(24*time.Hour))
	defer func() { _ = alive.Close() }()

	thisUpdate := now.Add(-time.Minute)
	nextUpdate := now.Add(24 * time.Hour)
	revokeAt := now.Add(-30 * time.Second)

	b, err := x509.NewCRLBuilder(ca.cert)
	if err != nil {
		t.Fatalf("NewCRLBuilder: %v", err)
	}
	defer func() { _ = b.Close() }()

	if err := b.SetNumber(7); err != nil {
		t.Fatalf("SetNumber: %v", err)
	}
	if err := b.SetThisUpdate(thisUpdate); err != nil {
		t.Fatalf("SetThisUpdate: %v", err)
	}
	if err := b.SetNextUpdate(nextUpdate); err != nil {
		t.Fatalf("SetNextUpdate: %v", err)
	}
	if err := b.Revoke(revoked1, revokeAt, x509.ReasonKeyCompromise); err != nil {
		t.Fatalf("Revoke(1): %v", err)
	}
	if err := b.Revoke(revoked2, revokeAt, x509.ReasonCessationOfOperation); err != nil {
		t.Fatalf("Revoke(2): %v", err)
	}

	crl, err := b.Sign(ca.priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	defer func() { _ = crl.Close() }()

	// 构建器在 Sign 之后失效。
	if _, err := b.Sign(ca.priv); err == nil {
		t.Error("第二次 Sign 应报错（句柄已转移）")
	}
	if err := b.Revoke(revoked1, revokeAt, x509.ReasonKeyCompromise); err == nil {
		t.Error("Sign 之后 Revoke 应报错")
	}
	if err := b.SetNumber(8); err == nil {
		t.Error("Sign 之后 SetNumber 应报错")
	}
	if err := b.Close(); err != nil {
		t.Errorf("已签发的 builder Close 应为 nil，got %v", err)
	}

	// 元数据
	if got := crl.Number(); got != 7 {
		t.Errorf("Number = %d, want 7", got)
	}
	if got := crl.Version(); got != 1 {
		t.Errorf("Version = %d, want 1 (v2)", got)
	}
	if got := crl.LastUpdate(); !got.Equal(thisUpdate.UTC().Truncate(time.Second)) {
		t.Errorf("LastUpdate = %v, want %v", got, thisUpdate.UTC())
	}
	if got := crl.NextUpdate(); !got.Equal(nextUpdate.UTC().Truncate(time.Second)) {
		t.Errorf("NextUpdate = %v, want %v", got, nextUpdate.UTC())
	}
	if got := crl.IssuerText(); got != ca.cert.SubjectText() {
		t.Errorf("IssuerText = %q, want %q", got, ca.cert.SubjectText())
	}
	// AKID 自动补齐，且与 CA 的 SKID 一致。
	if !bytes.Equal(crl.AuthorityKeyID(), ca.cert.SubjectKeyID()) {
		t.Errorf("AuthorityKeyID = %x, want CA SKID %x",
			crl.AuthorityKeyID(), ca.cert.SubjectKeyID())
	}

	// 吊销条目
	entries := crl.RevokedEntries()
	if len(entries) != 2 {
		t.Fatalf("RevokedEntries len = %d, want 2", len(entries))
	}
	wantReason := map[int64]string{1001: "keyCompromise", 1002: "cessationOfOperation"}
	for _, e := range entries {
		if want, ok := wantReason[e.Serial]; !ok {
			t.Fatalf("意外的序列号 %d", e.Serial)
		} else if e.Reason != want {
			t.Errorf("serial %d Reason = %q, want %q", e.Serial, e.Reason, want)
		}
		if !e.RevocationDate.Equal(revokeAt.UTC().Truncate(time.Second)) {
			t.Errorf("serial %d RevocationDate = %v, want %v",
				e.Serial, e.RevocationDate, revokeAt.UTC())
		}
	}

	// 签名可验证，且只有被吊销的两张证书命中。
	if err := crl.Verify(ca.cert); err != nil {
		t.Fatalf("CRL.Verify: %v", err)
	}
	if !crl.IsRevoked(revoked1) || !crl.IsRevoked(revoked2) {
		t.Error("IsRevoked 未命中已吊销证书")
	}
	if crl.IsRevoked(alive) {
		t.Error("IsRevoked 误报未吊销证书")
	}
	if err := x509.RevocationCheck(revoked1, []*x509.CRL{crl}); err == nil {
		t.Error("RevocationCheck(revoked1) 应报错")
	}
	if err := x509.RevocationCheck(alive, []*x509.CRL{crl}); err != nil {
		t.Errorf("RevocationCheck(alive) = %v, want nil", err)
	}

	// PEM / DER 往返后条目与元数据一致，且签名仍可验证。
	pemBytes, err := crl.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	derBytes, err := crl.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalDER: %v", err)
	}
	for _, tc := range []struct {
		name string
		load func([]byte) (*x509.CRL, error)
		data []byte
	}{
		{"PEM", x509.LoadCRLPEM, pemBytes},
		{"DER", x509.LoadCRLDER, derBytes},
		{"auto", x509.ParseCRL, pemBytes},
	} {
		reloaded, err := tc.load(tc.data)
		if err != nil {
			t.Fatalf("%s 往返加载失败：%v", tc.name, err)
		}
		if got := reloaded.Number(); got != 7 {
			t.Errorf("%s Number = %d, want 7", tc.name, got)
		}
		if got := len(reloaded.RevokedEntries()); got != 2 {
			t.Errorf("%s RevokedEntries len = %d, want 2", tc.name, got)
		}
		if err := reloaded.Verify(ca.cert); err != nil {
			t.Errorf("%s 往返后 CRL.Verify = %v", tc.name, err)
		}
		if err := reloaded.Close(); err != nil {
			t.Errorf("%s Close: %v", tc.name, err)
		}
	}
}

// TestCRLBuilderAlgorithms 验证 SM2 / RSA / EC / Ed25519 / Ed448 五种算法签发
// 的 CRL 其签名均可被对应 CA 公钥验证通过。
//
// TestCRLBuilderAlgorithms verifies that CRLs signed with SM2 / RSA / EC /
// Ed25519 / Ed448 all verify against the matching CA public key.
func TestCRLBuilderAlgorithms(t *testing.T) {
	for name, gen := range crlAlgorithms() {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			ca := newCA(t, "CRL "+name+" CA", gen,
				now.Add(-time.Hour), now.Add(24*time.Hour))
			defer func() { _ = ca.cert.Close() }()
			defer mustCloseAsym(t, ca.priv)

			b, err := x509.NewCRLBuilder(ca.cert)
			if err != nil {
				t.Fatalf("NewCRLBuilder: %v", err)
			}
			defer func() { _ = b.Close() }()
			if err := b.SetThisUpdate(now.Add(-time.Minute)); err != nil {
				t.Fatalf("SetThisUpdate: %v", err)
			}
			if err := b.SetNextUpdate(now.Add(time.Hour)); err != nil {
				t.Fatalf("SetNextUpdate: %v", err)
			}
			if err := b.Revoke(ca.cert, now, x509.ReasonSuperseded); err != nil {
				t.Fatalf("Revoke: %v", err)
			}
			crl, err := b.Sign(ca.priv)
			if err != nil {
				t.Fatalf("Sign(%s): %v", name, err)
			}
			defer func() { _ = crl.Close() }()

			if got := crl.SignatureAlgorithm(); got == "" {
				t.Error("SignatureAlgorithm 为空")
			}
			if err := crl.Verify(ca.cert); err != nil {
				t.Errorf("CRL.Verify(%s): %v", name, err)
			}
			if got := len(crl.RevokedEntries()); got != 1 {
				t.Errorf("RevokedEntries len = %d, want 1", got)
			}
			// 默认 CRL Number = 1（与 openssl ca -gencrl 一致）
			if got := crl.Number(); got != 1 {
				t.Errorf("默认 Number = %d, want 1", got)
			}
		})
	}
}

// TestCRLBuilderErrorPaths 验证构建器与 CRL 各错误路径：nil issuer、未设
// thisUpdate 即签名、nil 证书、非法原因码、以及已关闭 CRL 上的各项操作。
//
// TestCRLBuilderErrorPaths verifies the error paths of the builder and CRL:
// nil issuer, signing without thisUpdate, nil certificate, an invalid reason
// code, and operations on a closed CRL.
func TestCRLBuilderErrorPaths(t *testing.T) {
	now := time.Now()

	if _, err := x509.NewCRLBuilder(nil); err == nil {
		t.Error("NewCRLBuilder(nil) 应报错")
	}

	ca := newCA(t, "CRL Error CA", func() (asym.PrivateKey, error) {
		return asym.GenerateEd25519()
	}, now.Add(-time.Hour), now.Add(24*time.Hour))
	defer func() { _ = ca.cert.Close() }()
	defer mustCloseAsym(t, ca.priv)

	// 未设置 thisUpdate 即签名。
	b1, err := x509.NewCRLBuilder(ca.cert)
	if err != nil {
		t.Fatalf("NewCRLBuilder: %v", err)
	}
	defer func() { _ = b1.Close() }()
	if _, err := b1.Sign(ca.priv); err == nil {
		t.Error("未设 thisUpdate 即 Sign 应报错")
	}

	b2, err := x509.NewCRLBuilder(ca.cert)
	if err != nil {
		t.Fatalf("NewCRLBuilder: %v", err)
	}
	defer func() { _ = b2.Close() }()
	if err := b2.SetThisUpdate(now); err != nil {
		t.Fatalf("SetThisUpdate: %v", err)
	}
	if err := b2.Revoke(nil, now, x509.ReasonKeyCompromise); err == nil {
		t.Error("Revoke(nil) 应报错")
	}
	if err := b2.Revoke(ca.cert, now, x509.RevocationReason(7)); err == nil {
		t.Error("Revoke 保留原因码 7 应报错")
	}
	if err := b2.Revoke(ca.cert, now, x509.RevocationReason(99)); err == nil {
		t.Error("Revoke 越界原因码应报错")
	}
	if _, err := b2.Sign(nil); err == nil {
		t.Error("Sign(nil) 应报错")
	}

	// 已关闭 CRL 上的操作。
	crl, err := b2.Sign(ca.priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := crl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := crl.Close(); err != nil {
		t.Errorf("重复 Close 应为 nil，got %v", err)
	}
	// 关闭后仅剩的写路径（导出）必须明确失败，而不是静默产出空数据。
	if _, err := crl.MarshalPEM(); err == nil {
		t.Error("已关闭 CRL 的 MarshalPEM 应报错")
	}
	if _, err := crl.MarshalDER(); err == nil {
		t.Error("已关闭 CRL 的 MarshalDER 应报错")
	}
	if err := crl.Verify(ca.cert); err == nil {
		t.Error("已关闭 CRL 的 Verify 应报错")
	}

	// nil 构建器：所有方法都应返回错误而不是 panic。
	var nilBuilder *x509.CRLBuilder
	if _, err := nilBuilder.Sign(ca.priv); err == nil {
		t.Error("nil builder Sign 应报错")
	}
	if err := nilBuilder.SetNumber(1); err == nil {
		t.Error("nil builder SetNumber 应报错")
	}
	if err := nilBuilder.Close(); err != nil {
		t.Errorf("nil builder Close 应为 nil，got %v", err)
	}
}

// TestStoreSetTime 验证 Store.SetTime 让「已过期」证书链在指定历史时刻验证通过，
// 且不设置时仍按当前时刻判为过期（证书链校验失败为 *x509.VerifyError）。
//
// TestStoreSetTime verifies that Store.SetTime makes an expired chain validate
// as of a historical instant, while without it the same chain still fails as
// expired (reported as *x509.VerifyError).
func TestStoreSetTime(t *testing.T) {
	notBefore := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	caNotAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	leafNotAfter := time.Date(2020, 12, 31, 0, 0, 0, 0, time.UTC)

	ca := newCA(t, "Store Time CA", func() (asym.PrivateKey, error) {
		return asym.GenerateEC(asym.CurveP256)
	}, notBefore, caNotAfter)
	defer func() { _ = ca.cert.Close() }()
	defer mustCloseAsym(t, ca.priv)

	leaf := newLeaf(t, "store-time.example", 2001, ca, notBefore, leafNotAfter)
	defer func() { _ = leaf.Close() }()

	store := x509.NewStore()
	if err := store.AddCert(ca.cert); err != nil {
		t.Fatalf("AddCert: %v", err)
	}

	// 不指定时刻：叶证书已过期，链验证必须失败且错误码为「已过期」。
	if _, err := x509.ChainVerify(leaf, store, nil); err == nil {
		t.Fatal("过期证书链在当前时刻应验证失败")
	} else {
		var ve *x509.VerifyError
		if !errors.As(err, &ve) {
			t.Fatalf("期望 *x509.VerifyError，got %T: %v", err, err)
		}
		if ve.Code != 10 { // X509_V_ERR_CERT_HAS_EXPIRED
			t.Errorf("错误码 = %d (%s), want 10 (certificate has expired)",
				ve.Code, ve.Message)
		}
	}

	// 指定历史时刻：叶证书在有效期内，链验证应通过。
	at := time.Date(2020, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := store.SetTime(at); err != nil {
		t.Fatalf("SetTime: %v", err)
	}
	chain, err := x509.ChainVerify(leaf, store, nil)
	if err != nil {
		t.Fatalf("SetTime 后链验证失败：%v", err)
	}
	for _, c := range chain {
		if err := c.Close(); err != nil {
			t.Errorf("chain Close: %v", err)
		}
	}

	// 指定到叶证书生效之前：应按「尚未生效」失败。
	if err := store.SetTime(time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("SetTime(2019): %v", err)
	}
	if _, err := x509.ChainVerify(leaf, store, nil); err == nil {
		t.Error("SetTime(2019) 时证书尚未生效，链验证应失败")
	}
}

// TestVerifyHostname 验证主机名 / IP 校验：SAN dNSName 命中与未命中、通配符、
// SAN iPAddress 命中与未命中、无 SAN 时回退 CN，以及空主机名被拒绝。
//
// TestVerifyHostname verifies host name / IP matching: SAN dNSName hits and
// misses, wildcards, SAN iPAddress hits and misses, the CN fallback when no
// SAN is present, and rejection of an empty host name.
func TestVerifyHostname(t *testing.T) {
	now := time.Now()
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	defer mustCloseAsym(t, priv)

	build := func(t *testing.T, cn, san string) *x509.Certificate {
		t.Helper()
		cert := x509.NewCertificate()
		subject := x509.NewName().Add("CN", cn)
		if err := cert.SetSubject(subject); err != nil {
			t.Fatalf("SetSubject: %v", err)
		}
		if err := cert.SetIssuer(subject); err != nil {
			t.Fatalf("SetIssuer: %v", err)
		}
		if err := cert.SetVersion(2); err != nil {
			t.Fatalf("SetVersion: %v", err)
		}
		if err := cert.SetSerial(1); err != nil {
			t.Fatalf("SetSerial: %v", err)
		}
		if err := cert.SetValidity(now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
			t.Fatalf("SetValidity: %v", err)
		}
		if err := cert.SetPublicKey(priv.Public()); err != nil {
			t.Fatalf("SetPublicKey: %v", err)
		}
		if san != "" {
			if err := cert.AddSubjectAltName(san); err != nil {
				t.Fatalf("AddSubjectAltName: %v", err)
			}
		}
		if err := cert.Sign(priv); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return cert
	}

	withSAN := build(t, "fallback.example",
		"DNS:example.com,DNS:*.wild.example,IP:192.0.2.1")
	defer func() { _ = withSAN.Close() }()

	for _, tc := range []struct {
		host string
		ok   bool
	}{
		{"example.com", true},
		{"EXAMPLE.com", true}, // 主机名匹配大小写不敏感
		{"other.example", false},
		{"a.wild.example", true},    // 通配符命中一级
		{"a.b.wild.example", false}, // 通配符不跨多级
		{"192.0.2.1", true},         // SAN iPAddress
		{"192.0.2.2", false},
		{"fallback.example", false}, // 有 dNSName SAN 时不回退 CN
	} {
		err := withSAN.VerifyHostname(tc.host)
		if tc.ok && err != nil {
			t.Errorf("VerifyHostname(%q) = %v, want nil", tc.host, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("VerifyHostname(%q) = nil, want error", tc.host)
		}
	}
	if err := withSAN.VerifyHostname(""); err == nil {
		t.Error("VerifyHostname(\"\") 应报错")
	}

	// 无 SAN 时回退 subject CN。
	noSAN := build(t, "cn-only.example", "")
	defer func() { _ = noSAN.Close() }()
	if err := noSAN.VerifyHostname("cn-only.example"); err != nil {
		t.Errorf("CN 回退失败：%v", err)
	}
	if err := noSAN.VerifyHostname("other.example"); err == nil {
		t.Error("无 SAN 且 CN 不匹配时应报错")
	}

	var nilCert *x509.Certificate
	if err := nilCert.VerifyHostname("example.com"); err == nil {
		t.Error("nil 证书 VerifyHostname 应报错")
	}
}
