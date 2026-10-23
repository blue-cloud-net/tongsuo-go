package x509

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// TestCertificateAddCertificatePolicies 验证 certificatePolicies（OID 2.5.29.32）
// 扩展可以创建，并逐字节校验其 DER 编码。
//
// 回归用例：该扩展在 OpenSSL 中属于 r2i（raw）类扩展，解析时要求扩展上下文中
// 存在配置库；本库此前构造上下文时未注入配置库，导致
// "X509 V3 routines::no config database"（0x11000088），且在 CSR 路径上
// 因上下文为 NULL 而直接段错误。
//
// 期望值按 RFC 5280 §4.2.1.4 的 ASN.1 定义推导：
//
//	CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
//	PolicyInformation ::= SEQUENCE { policyIdentifier OBJECT IDENTIFIER,
//	                                policyQualifiers SEQUENCE OF ... OPTIONAL }
//
// TestCertificateAddCertificatePolicies verifies that the certificatePolicies
// extension (OID 2.5.29.32) can be created and checks its DER encoding byte
// for byte.
//
// Regression case: this extension is an r2i (raw) extension in OpenSSL, whose
// parser requires a configuration database in the extension context. The
// library used to build that context without a configuration database, which
// produced "X509 V3 routines::no config database" (0x11000088) and, on the CSR
// path, a segmentation fault due to the NULL context.
//
// The expected values are derived from the ASN.1 definition in RFC 5280
// §4.2.1.4:
//
//	CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
//	PolicyInformation ::= SEQUENCE { policyIdentifier OBJECT IDENTIFIER,
//	                                policyQualifiers SEQUENCE OF ... OPTIONAL }
func TestCertificateAddCertificatePolicies(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		value     string
		wantCrit  bool
		wantDER   string
		wantOID   string
		wantField string
	}{
		{
			name:      "single policy",
			value:     "1.2.3.4",
			wantCrit:  false,
			wantDER:   "3007300506032a0304",
			wantOID:   "2.5.29.32",
			wantField: "certificatePolicies",
		},
		{
			name:      "single policy critical",
			value:     "critical,1.2.3.4",
			wantCrit:  true,
			wantDER:   "3007300506032a0304",
			wantOID:   "2.5.29.32",
			wantField: "certificatePolicies",
		},
		{
			name:      "two policies with ia5org",
			value:     "ia5org,1.2.3.4,1.5.6.7.8",
			wantCrit:  false,
			wantDER:   "300f300506032a0304300606042d060708",
			wantOID:   "2.5.29.32",
			wantField: "certificatePolicies",
		},
		{
			name:      "anyPolicy",
			value:     "2.5.29.32.0",
			wantCrit:  false,
			wantDER:   "300830060604551d2000",
			wantOID:   "2.5.29.32",
			wantField: "certificatePolicies",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := newUnsignedCert(t, priv)
			t.Cleanup(func() { _ = cert.Close() })

			if err := cert.AddExtensionByName("certificatePolicies", tt.value); err != nil {
				t.Fatalf("AddExtensionByName(certificatePolicies, %q): %v", tt.value, err)
			}
			if !cert.HasExtension("certificatePolicies") {
				t.Fatal("certificatePolicies missing after add")
			}

			var found bool
			for _, e := range cert.Extensions() {
				if e.Field != tt.wantField {
					continue
				}
				found = true
				if e.OID != tt.wantOID {
					t.Errorf("OID = %q, want %q", e.OID, tt.wantOID)
				}
				if e.Critical != tt.wantCrit {
					t.Errorf("Critical = %v, want %v", e.Critical, tt.wantCrit)
				}
				if got := hex.EncodeToString(e.Data); got != tt.wantDER {
					t.Errorf("DER = %s, want %s", got, tt.wantDER)
				}
			}
			if !found {
				t.Fatalf("certificatePolicies not found in Extensions(): %v", cert.Extensions())
			}
		})
	}
}

// TestCertificateCertificatePoliciesRoundTrip 验证 certificatePolicies 扩展在
// 签名并经 PEM 往返后仍然完整可读。
//
// TestCertificateCertificatePoliciesRoundTrip verifies that the
// certificatePolicies extension stays intact after signing and a PEM round
// trip.
func TestCertificateCertificatePoliciesRoundTrip(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	cert := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = cert.Close() })

	if err := cert.AddExtensionByName("certificatePolicies", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}
	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = loaded.Close() })

	if err := loaded.Verify(priv.Public()); err != nil {
		t.Fatalf("verify after PEM round trip: %v", err)
	}
	var found bool
	for _, e := range loaded.Extensions() {
		if e.Field == "certificatePolicies" {
			found = true
			if got := hex.EncodeToString(e.Data); got != "3007300506032a0304" {
				t.Errorf("DER after round trip = %s, want 3007300506032a0304", got)
			}
		}
	}
	if !found {
		t.Fatalf("certificatePolicies lost after PEM round trip: %v", loaded.Extensions())
	}
}

// TestCertificateReplaceCertificatePolicies 验证 ReplaceExtension 能覆盖
// certificatePolicies，且保持扩展在证书中的原有位置。
//
// TestCertificateReplaceCertificatePolicies verifies that ReplaceExtension can
// overwrite the certificatePolicies extension and keeps the extension at its
// original position.
func TestCertificateReplaceCertificatePolicies(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	cert := newUnsignedCert(t, priv)
	t.Cleanup(func() { _ = cert.Close() })

	// 先加一条 SAN 作为位置锚点，再加 certificatePolicies。
	if err := cert.AddExtensionByName("subjectAltName", "DNS:anchor.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddExtensionByName("certificatePolicies", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	loc := -1
	for i, e := range cert.Extensions() {
		if e.Field == "certificatePolicies" {
			loc = i
		}
	}
	if loc < 0 {
		t.Fatalf("certificatePolicies not found: %v", cert.Extensions())
	}

	if err := cert.ReplaceExtension("certificatePolicies", "1.2.3.5"); err != nil {
		t.Fatalf("ReplaceExtension: %v", err)
	}

	exts := cert.Extensions()
	if len(exts) != 2 {
		t.Fatalf("Extensions() = %d entries, want 2: %v", len(exts), exts)
	}
	if exts[loc].Field != "certificatePolicies" {
		t.Fatalf("extension moved: index %d is %q, want certificatePolicies", loc, exts[loc].Field)
	}
	// 1.2.3.5 → OID 06 03 2A 03 05
	if got := hex.EncodeToString(exts[loc].Data); got != "3007300506032a0305" {
		t.Errorf("DER after replace = %s, want 3007300506032a0305", got)
	}
}

// TestCertificateSANEmailCopy 验证 subjectAltName 的 "email:copy" 值可用：
// 该值要求扩展上下文中的 subject 证书提供 emailAddress。
//
// 回归用例：此前扩展上下文既未注入配置库，也未传入 subject 证书，
// "email:copy" 这类依赖 subject 信息的值无法解析。
//
// TestCertificateSANEmailCopy verifies that the "email:copy" value of
// subjectAltName works: it requires the subject certificate in the extension
// context to supply the emailAddress.
//
// Regression case: the extension context used to carry neither a configuration
// database nor the subject certificate, so values reading subject information
// could not be parsed.
func TestCertificateSANEmailCopy(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	cert := newCertWithEmailSubject(t, priv, "copy.example.com", "ops@example.com")
	t.Cleanup(func() { _ = cert.Close() })

	if err := cert.AddSubjectAltName("email:copy"); err != nil {
		t.Fatalf("AddSubjectAltName(email:copy): %v", err)
	}
	sans := cert.SAN()
	if len(sans) != 1 {
		t.Fatalf("SAN() = %v, want exactly one entry copied from the subject", sans)
	}
	if !strings.Contains(sans[0], "ops@example.com") {
		t.Fatalf("SAN() = %v, want it to contain ops@example.com", sans)
	}
}

// TestCertificateSANEmailCopyViaMerge 验证可重复 OID 的**合并**路径同样具备
// subject 上下文：第二次添加 subjectAltName 走合并分支，其值 "email:copy"
// 需要从 subject 读取 emailAddress。
//
// 回归用例：合并路径原先以 NULL 上下文解析新值，导致 "email:copy" 在合并时
// 失败——这是本次修复中唯一独立于普通追加路径的改动。
//
// TestCertificateSANEmailCopyViaMerge verifies that the **merge** path of a
// repeatable OID carries the subject context as well: the second
// subjectAltName addition takes the merge branch, whose value "email:copy"
// needs the emailAddress from the subject.
//
// Regression case: the merge helper used to parse the new value with a NULL
// context, so "email:copy" failed when merging — the only change in this fix
// that is independent of the plain append path.
func TestCertificateSANEmailCopyViaMerge(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	cert := newCertWithEmailSubject(t, priv, "merge-copy.example.com", "merge@example.com")
	t.Cleanup(func() { _ = cert.Close() })

	// 第一次：普通追加路径。
	if err := cert.AddSubjectAltName("DNS:merge-copy.example.com"); err != nil {
		t.Fatalf("first AddSubjectAltName: %v", err)
	}
	// 第二次：触发合并路径，且值依赖 subject 上下文。
	if err := cert.AddSubjectAltName("email:copy"); err != nil {
		t.Fatalf("AddSubjectAltName(email:copy) on merge path: %v", err)
	}

	sans := cert.SAN()
	if len(sans) != 2 {
		t.Fatalf("SAN() = %v, want 2 entries after merge", sans)
	}
	var hasEmail bool
	for _, s := range sans {
		if strings.Contains(s, "merge@example.com") {
			hasEmail = true
		}
	}
	if !hasEmail {
		t.Fatalf("SAN() = %v, want it to contain merge@example.com", sans)
	}
	// 合并必须仍只有一条 SAN 扩展条目（重复条目会让 SAN() 全部失效）。
	sanCount := 0
	for _, e := range cert.Extensions() {
		if e.Field == "subjectAltName" {
			sanCount++
		}
	}
	if sanCount != 1 {
		t.Fatalf("subjectAltName entries = %d, want exactly 1", sanCount)
	}

	// 合并结果必须真的能用于主机名校验。
	if err := cert.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("merge-copy.example.com"); err != nil {
		t.Errorf("VerifyHostname after merge: %v", err)
	}
}

// newCertWithEmailSubject 构建一张 subject 含 emailAddress 的未签名证书，
// 供 subjectAltName 的 "email:copy" 用例复用。
//
// newCertWithEmailSubject builds a not-yet-signed certificate whose subject
// carries an emailAddress, for reuse by the subjectAltName "email:copy" cases.
func newCertWithEmailSubject(t *testing.T, priv asym.PrivateKey, cn, email string) *Certificate {
	t.Helper()
	now := time.Now()
	subject := NewName().Add("CN", cn).Add("emailAddress", email)
	cert := NewCertificate()
	if err := cert.SetVersion(2); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(9102); err != nil {
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
	return cert
}

// TestCSRAddCertificatePolicies 验证 CSR 侧可以创建 certificatePolicies 扩展，
// 并逐字节校验其 DER 编码。
//
// 回归用例：CSR 路径此前以 NULL 上下文构造扩展，而 certificatePolicies 属于
// r2i 类扩展、其解析器会直接解引用上下文中的配置库指针——结果是整个进程
// 段错误（SIGSEGV），而不是一个可返回的错误。
//
// TestCSRAddCertificatePolicies verifies that the certificatePolicies
// extension can be created on a certificate request and checks its DER
// encoding byte for byte.
//
// Regression case: the CSR path used to build the extension with a NULL
// context. certificatePolicies is an r2i-style extension whose parser
// dereferences the configuration database pointer in the context, so the whole
// process died with SIGSEGV instead of returning an error.
func TestCSRAddCertificatePolicies(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	req := NewEmptyCertificateRequest()
	if err := req.SetSubject(NewName().Add("CN", "csr-certpol.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := req.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}

	if err := req.AddExtensionByName("certificatePolicies", "1.2.3.4"); err != nil {
		t.Fatalf("AddExtensionByName(certificatePolicies): %v", err)
	}

	var found bool
	for _, e := range req.Extensions() {
		if e.Field != "certificatePolicies" {
			continue
		}
		found = true
		if e.OID != "2.5.29.32" {
			t.Errorf("OID = %q, want 2.5.29.32", e.OID)
		}
		if got := hex.EncodeToString(e.Data); got != "3007300506032a0304" {
			t.Errorf("DER = %s, want 3007300506032a0304", got)
		}
	}
	if !found {
		t.Fatalf("certificatePolicies not found in CSR Extensions(): %v", req.Extensions())
	}

	// 签名并经 DER 往返后仍应存在。
	if err := req.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := req.Verify(); err != nil {
		t.Fatalf("CSR verify: %v", err)
	}
	der, err := req.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := LoadCertificateRequestDER(der)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	var found2 bool
	for _, e := range reparsed.Extensions() {
		if e.Field == "certificatePolicies" {
			found2 = true
			if got := hex.EncodeToString(e.Data); got != "3007300506032a0304" {
				t.Errorf("DER after round trip = %s, want 3007300506032a0304", got)
			}
		}
	}
	if !found2 {
		t.Fatalf("certificatePolicies lost after DER round trip: %v", reparsed.Extensions())
	}
}

// TestCSRSANEmailCopy 验证 CSR 侧 subjectAltName 的 "email:copy" 值可用：
// 该值要求扩展上下文中的 subject 来源提供 emailAddress，CSR 场景下由
// 请求自身充当。
//
// 回归用例：此前 CSR 的扩展上下文既未注入配置库，也未传入请求自身，
// "email:copy" 无法解析。
//
// TestCSRSANEmailCopy verifies that the "email:copy" value of subjectAltName
// works on a certificate request: the request itself supplies the subject
// information in that case.
//
// Regression case: the CSR extension context used to carry neither a
// configuration database nor the request itself, so "email:copy" could not be
// parsed.
func TestCSRSANEmailCopy(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	req := NewEmptyCertificateRequest()
	subject := NewName().Add("CN", "csr-copy.example.com").Add("emailAddress", "ops@example.com")
	if err := req.SetSubject(subject); err != nil {
		t.Fatal(err)
	}
	if err := req.SetPublicKey(priv.Public()); err != nil {
		t.Fatal(err)
	}

	if err := req.AddExtensionByName("subjectAltName", "email:copy"); err != nil {
		t.Fatalf("AddExtensionByName(subjectAltName, email:copy): %v", err)
	}
	var found bool
	for _, e := range req.Extensions() {
		if e.Field != "subjectAltName" {
			continue
		}
		found = true
		// 扩展值为 GENERAL_NAMES 的 DER；其中应含 ops@example.com。
		if !strings.Contains(string(e.Data), "ops@example.com") {
			t.Errorf("SAN extension data %q does not contain ops@example.com", e.Data)
		}
	}
	if !found {
		t.Fatalf("subjectAltName not found in CSR Extensions(): %v", req.Extensions())
	}
}
