package x509_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// selfSignedAlgorithms 返回参与自签用例的算法集合。
//
// selfSignedAlgorithms returns the algorithm set used by the self-signed
// tests.
func selfSignedAlgorithms() map[string]func() (asym.PrivateKey, error) {
	return map[string]func() (asym.PrivateKey, error){
		"SM2":     func() (asym.PrivateKey, error) { return asym.GenerateSM2() },
		"RSA":     func() (asym.PrivateKey, error) { return asym.GenerateRSA(2048) },
		"EC":      func() (asym.PrivateKey, error) { return asym.GenerateEC(asym.CurveP256) },
		"Ed25519": func() (asym.PrivateKey, error) { return asym.GenerateEd25519() },
		"Ed448":   func() (asym.PrivateKey, error) { return asym.GenerateEd448() },
	}
}

// TestCreateSelfSigned 验证各算法下 CreateSelfSigned 的完整语义：
// issuer == subject、SKID 与 AKID 均已补齐且一致、签名可经链验证通过、
// PEM/DER 往返后仍可验证。
//
// TestCreateSelfSigned verifies the full semantics of CreateSelfSigned across
// algorithms: issuer == subject, SKID and AKID both present and equal, the
// signature passing chain verification, and the certificate surviving a
// PEM/DER round trip with its signature still valid.
func TestCreateSelfSigned(t *testing.T) {
	for name, gen := range selfSignedAlgorithms() {
		t.Run(name, func(t *testing.T) {
			priv, err := gen()
			if err != nil {
				t.Fatalf("generate %s: %v", name, err)
			}
			defer func() {
				if err := asym.Close(priv); err != nil {
					t.Errorf("Close: %v", err)
				}
			}()

			subject := x509.NewName().Add("CN", "self-"+name).Add("O", "tongsuo-go")
			now := time.Now()
			cert, err := x509.CreateSelfSigned(subject, 42,
				now.Add(-time.Minute), now.Add(24*time.Hour), priv.Public(), priv)
			if err != nil {
				t.Fatalf("CreateSelfSigned(%s): %v", name, err)
			}
			defer func() {
				if err := cert.Close(); err != nil {
					t.Errorf("cert.Close: %v", err)
				}
			}()

			// issuer == subject
			if cert.SubjectText() != cert.IssuerText() {
				t.Errorf("issuer %q != subject %q", cert.IssuerText(), cert.SubjectText())
			}
			if got := cert.Subject(); got != "self-"+name {
				t.Errorf("Subject CN = %q, want %q", got, "self-"+name)
			}
			if got := cert.Serial(); got != 42 {
				t.Errorf("Serial = %d, want 42", got)
			}
			if got := cert.Version(); got != 2 {
				t.Errorf("Version = %d, want 2 (v3)", got)
			}
			// 有效期
			if !cert.NotBefore().Before(now.Add(time.Second)) || !cert.NotAfter().After(now) {
				t.Errorf("有效期不符：%v ~ %v", cert.NotBefore(), cert.NotAfter())
			}

			// v3 + SKID/AKID 自动补齐，且两者一致（自签）
			skid := cert.SubjectKeyID()
			akid := cert.AuthorityKeyID()
			if len(skid) == 0 {
				t.Error("subjectKeyIdentifier 未补齐")
			}
			if len(akid) == 0 {
				t.Error("authorityKeyIdentifier 未补齐")
			}
			if !bytes.Equal(skid, akid) {
				t.Errorf("自签证书 SKID(%x) 应等于 AKID(%x)", skid, akid)
			}

			// 签名有效：以自身为信任锚做链验证（真正的验签路径）
			store := x509.NewStore()
			if err := store.AddCert(cert); err != nil {
				t.Fatalf("AddCert: %v", err)
			}
			chain, err := x509.ChainVerify(cert, store, nil)
			if err != nil {
				t.Fatalf("ChainVerify: %v", err)
			}
			if len(chain) == 0 {
				t.Fatal("ChainVerify 返回空链")
			}

			// PEM / DER 往返后仍可验证
			for _, enc := range []struct {
				name string
				data []byte
			}{
				{"PEM", mustMarshalPEM(t, cert)},
				{"DER", mustMarshalDER(t, cert)},
			} {
				var reloaded *x509.Certificate
				var err error
				if enc.name == "PEM" {
					reloaded, err = x509.LoadCertificatePEM(enc.data)
				} else {
					reloaded, err = x509.LoadCertificateDER(enc.data)
				}
				if err != nil {
					t.Fatalf("%s 往返加载失败：%v", enc.name, err)
				}
				st2 := x509.NewStore()
				if err := st2.AddCert(reloaded); err != nil {
					t.Fatalf("%s AddCert: %v", enc.name, err)
				}
				if _, err := x509.ChainVerify(reloaded, st2, nil); err != nil {
					t.Errorf("%s 往返后链验证失败：%v", enc.name, err)
				}
				if err := reloaded.Close(); err != nil {
					t.Errorf("%s Close: %v", enc.name, err)
				}
			}
		})
	}
}

// mustMarshalPEM 导出证书 PEM，失败即终止。
//
// mustMarshalPEM exports the certificate as PEM, failing the test on error.
func mustMarshalPEM(t *testing.T, c *x509.Certificate) []byte {
	t.Helper()
	b, err := c.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	return b
}

// mustMarshalDER 导出证书 DER，失败即终止。
//
// mustMarshalDER exports the certificate as DER, failing the test on error.
func mustMarshalDER(t *testing.T, c *x509.Certificate) []byte {
	t.Helper()
	b, err := c.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalDER: %v", err)
	}
	return b
}

// TestCreateSelfSignedNilParams 验证 nil 参数被拒绝。
//
// TestCreateSelfSignedNilParams verifies that nil parameters are rejected.
func TestCreateSelfSignedNilParams(t *testing.T) {
	priv, err := asym.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(priv) }()
	subject := x509.NewName().Add("CN", "nil-params")
	now := time.Now()

	if _, err := x509.CreateSelfSigned(nil, 1, now, now.Add(time.Hour), priv.Public(), priv); err == nil {
		t.Error("nil subject 应报错")
	}
	if _, err := x509.CreateSelfSigned(subject, 1, now, now.Add(time.Hour), nil, priv); err == nil {
		t.Error("nil pub 应报错")
	}
	if _, err := x509.CreateSelfSigned(subject, 1, now, now.Add(time.Hour), priv.Public(), nil); err == nil {
		t.Error("nil signer 应报错")
	}
}

// TestCreateSelfSignedUnsupportedKeyType 说明类型层面为何无需运行时守卫：
// `asym.PublicKey` / `asym.PrivateKey` 接口含有非导出方法（`corePKey()`），
// 因此**包外类型无法实现它们**，传错类型在编译期就被拦住。
// 本用例只锚定这一事实（对称密钥、`*core.PKey`、字符串均无法作为参数类型）。
//
// TestCreateSelfSignedUnsupportedKeyType records why no runtime guard is needed
// at the type level: asym.PublicKey / asym.PrivateKey carry an unexported method
// (corePKey()), so types outside the package cannot implement them and mismatches
// are rejected at compile time.
func TestCreateSelfSignedUnsupportedKeyType(t *testing.T) {
	priv, err := asym.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = asym.Close(priv) }()

	var pub asym.PublicKey = priv.Public()
	var signer asym.PrivateKey = priv
	// 下面两行取消注释应**编译失败**（接口含非导出方法）：
	//   var _ asym.PublicKey = (*core.PKey)(nil)
	//   var _ asym.PublicKey = "not-a-key"
	_ = pub
	_ = signer

	subject := x509.NewName().Add("CN", "type-level")
	now := time.Now()
	cert, err := x509.CreateSelfSigned(subject, 1, now, now.Add(time.Hour), pub, signer)
	if err != nil {
		t.Fatalf("CreateSelfSigned: %v", err)
	}
	if err := cert.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
