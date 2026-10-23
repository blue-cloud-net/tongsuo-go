// Package x509 基于铜锁原生实现实现 X.509 证书与证书签名请求（CSR）管理。
//
// 支持证书的 PEM 加载/导出、主题/签发者/有效期/序列号/公钥读取、
// 证书创建与签名（自签或 CA 签发）、CSR 生成与验证。
//
// 自 v0.3.0 起本包同时收口 PKI 家族：原独立 `ocsp` 包已并入（`ocsp.go`），
// 证书 / CSR / CRL / OCSP / 链验证均在同一包内（roadmap §3.10）。
//
// 密钥参数一律使用 `asym.PublicKey` / `asym.PrivateKey`：原 `x509.PublicKey` /
// `x509.PrivateKey` 窄接口已删除，公开签名中不再出现 `internal/` 类型
// （roadmap §5 E1-8/E1-9/E1-10/E1-11）。
//
// 内部按职责拆分为多个文件：
//
//	x509.go    — Certificate 主类型、Extension 类型、
//	             CreateCertificate / CreateSelfSigned、Set* 构建方法、Add* 扩展方法、签/验 / VerifyHostname
//	name.go    — Name / NameEntry / NewName
//	csr.go     — CertificateRequest（含 New/NewEmptyCertificateRequest 与所有 CSR 方法）
//	store.go   — Store / VerifyError / NewStore / ChainVerify / SetTime
//	crl.go     — CRL / RevokedEntry / CRLBuilder / RevocationReason / ParseCRL / RevocationCheck
//	ocsp.go    — OCSP 请求/响应：CreateOCSPRequest / ParseOCSPResponse / Response
//	helpers.go — convertEntries / convertExtensions（内部转换辅助）
//
// Package x509 provides X.509 certificate and certificate signing request
// (CSR) management built on the Tongsuo native library.
//
// It covers PEM loading and export of certificates, reading of subject /
// issuer / validity / serial number / public key, certificate creation and
// signing (self-signed or CA-issued), and CSR generation and verification.
//
// Since v0.3.0 the package also hosts the whole PKI family: the former
// standalone ocsp package has been merged in (ocsp.go), so certificates,
// CSR, CRL, OCSP and chain verification all live in one package
// (roadmap §3.10).
//
// Key parameters are always asym.PublicKey / asym.PrivateKey: the former narrow
// x509.PublicKey / x509.PrivateKey interfaces were removed, so no public
// signature mentions an internal/ type any more (roadmap §5, E1-8 / E1-9 / E1-10
// / E1-11).
//
// The package is split across files by responsibility:
//
//	x509.go    — Certificate main type, Extension type,
//	             CreateCertificate / CreateSelfSigned, Set* builders,
//	             Add* extension methods, sign / verify
//	name.go    — Name / NameEntry / NewName
//	csr.go     — CertificateRequest (New / NewEmptyCertificateRequest and
//	             all CSR methods)
//	store.go   — Store / VerifyError / NewStore / ChainVerify
//	crl.go     — CRL / RevokedEntry / ParseCRL / RevocationCheck
//	ocsp.go    — OCSP request / response: CreateOCSPRequest,
//	             ParseOCSPResponse, Response
//	helpers.go — convertEntries / convertExtensions (internal helpers)
package x509

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Certificate 表示一张 X.509 证书。
//
// Certificate represents an X.509 certificate.
type Certificate struct {
	cert    *core.Certificate
	closeMu sync.Mutex // 保护 closed 字段，使 Close 幂等。
	closed  bool
}

// Close 释放底层证书句柄。幂等。
//
// 成功 Close 后任何其他方法对该 *Certificate 调用会返回错误
// （操作类）或零值（查询类，参见 internal/core.Handle 合约）。
//
// Close releases the underlying X509 handle.
//
// The call is idempotent: invoking it on a nil receiver or on a
// certificate that has already been closed returns nil without further
// side effects. After Close returns, any other method on the same
// *Certificate returns the error "x509: certificate closed" (or a
// zero-value result for query-style methods, see the internal/core
// Handle contract).
//
// All ownership rules:
//   - LoadCertificatePEM / LoadCertificateDER / NewCertificate return a
//     *Certificate whose underlying *core.Certificate is owned solely by
//     that wrapper. Calling Close releases the native X509.
//   - Certificates obtained through the internal bridge
//     (internal/certaccess.Wrap, tls peer chains, pkcs7 / pkcs12 parsing)
//     also own their handles and must be Closed by whoever receives them.
//   - Config.Cert (TLS) is installed into SSL_CTX with X509_up_ref, so
//     closing the original *Certificate is safe.
func (c *Certificate) Close() error {
	if c == nil {
		return nil
	}
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.cert.Close()
}

// CoreCertificate 返回底层核心证书对象（供 internal/certaccess 桥接使用）。
//
// 本方法不属于稳定公共 API：它存在的唯一目的是让 tls / pkcs/pkcs7 /
// pkcs/pkcs12 跨包取到底层句柄，而这些消费方的公开签名中不得出现 internal/ 类型
// （roadmap §5 E1-8）。外部包即使满足该结构化断言，也无法 import internal/core，
// 因此拿到句柄也无法使用 —— 与 roadmap §5.2「残余瑕疵（已接受）」同理。
//
// CoreCertificate returns the underlying core certificate (used by the
// internal/certaccess bridge).
//
// This method is not part of the stable public API: it exists solely so that
// tls, pkcs/pkcs7 and pkcs/pkcs12 can reach the underlying handle while no
// public signature of those consumers mentions an internal/ type (roadmap §5,
// E1-8). An external package that satisfies the structural assertion still
// cannot import internal/core and therefore cannot use the result — the same
// accepted residual as roadmap §5.2.
func (c *Certificate) CoreCertificate() *core.Certificate { return c.cert }

// LoadCertificatePEM 从 PEM 加载证书。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// LoadCertificatePEM parses PEM-encoded certificate data and returns a *Certificate.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func LoadCertificatePEM(pemBytes []byte) (*Certificate, error) {
	c, err := core.LoadCertificatePEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return &Certificate{cert: c}, nil
}

// LoadCertificateDER 从 DER 编码加载证书。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// LoadCertificateDER parses DER-encoded certificate data and returns a *Certificate.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func LoadCertificateDER(der []byte) (*Certificate, error) {
	c, err := core.LoadCertificateDER(der)
	if err != nil {
		return nil, err
	}
	return &Certificate{cert: c}, nil
}

// LoadCertificatePEMFile 从 PEM 文件加载证书（等价 `openssl x509 -in <path>`）。
//
// 对应官方 SDK 的 LoadCertificateFromPEM 文件入口；本库不提供 PEM 解析辅助，
// 调用方也可自行 os.ReadFile + LoadCertificatePEM。
//
// 返回的证书拥有自己的句柄，调用方须调用 Close。
//
// 失败时返回包装了 OpError 的错误；文件不存在或读失败时返回带上下文的错误。
//
// LoadCertificatePEMFile loads a certificate from a PEM file (the equivalent of
// `openssl x509 -in <path>`).
//
// It corresponds to the official SDK's LoadCertificateFromPEM file entry
// point; since this package ships no PEM parsing helpers, callers may also do
// os.ReadFile plus LoadCertificatePEM themselves.
//
// The returned certificate owns its handle; the caller must Close it.
//
// On failure, it returns an error wrapping an OpError; a missing or unreadable
// file yields an error carrying that context.
func LoadCertificatePEMFile(path string) (*Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("x509: read %s: %w", path, err)
	}
	cert, err := LoadCertificatePEM(data)
	if err != nil {
		return nil, fmt.Errorf("x509: load %s: %w", path, err)
	}
	return cert, nil
}

// SaveCertificatePEMFile 把证书以 PEM 写入文件（等价 `openssl x509 -out <path>`）。
//
// perm 为文件权限（如 0o644）；文件已存在时按该权限截断覆写并重新 chmod
// （os.WriteFile 只在创建时应用权限，故此处显式补一次）。
// 写入的是**公开**证书，不含私钥；私钥请走 asym 包的 MarshalPrivateKeyPEM。
//
// 失败时返回包装了 OpError 的错误；文件写入失败时返回带上下文的错误。
//
// SaveCertificatePEMFile writes the certificate to a PEM file (the equivalent of
// `openssl x509 -out <path>`).
//
// perm is the file mode (for example 0o644); an existing file is truncated,
// overwritten and re-chmod'ed to that mode (os.WriteFile only applies the mode
// when creating the file, so this call sets it explicitly).
//
// Only the **public** certificate is written, never a private key; use the asym
// package's MarshalPrivateKeyPEM for keys.
//
// On failure, it returns an error wrapping an OpError; a failed write yields an
// error carrying that context.
func SaveCertificatePEMFile(path string, c *Certificate, perm os.FileMode) error {
	if c == nil {
		return fmt.Errorf("x509: nil certificate")
	}
	pemBytes, err := c.MarshalPEM()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, pemBytes, perm); err != nil {
		return fmt.Errorf("x509: write %s: %w", path, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("x509: chmod %s: %w", path, err)
	}
	return nil
}

// wrapCertificate 用底层核心证书构造 Certificate（包内辅助）。
//
// 实现方式是 **DER 往返**（`MarshalDER` → `LoadCertificateDER`），因此返回的
// *Certificate **拥有自己的句柄**，调用方需调用 Close；传入的 c 不受影响。
//
// 之所以保留为包内函数：原公开的 `WrapCertificate(c *core.Certificate)` 属于
// 「公开签名中出现 internal/ 类型」的泄漏（roadmap §5 E1 的目标），包外消费方改用
// `internal/certaccess.Wrap`（同样 DER 往返）。
//
// ⚠️ 与旧入口的语义差异：旧 `WrapCertificate` 是**共享句柄**（Close 会连带释放真正
// 的所有者），本函数产出 owned 副本 —— 这与 tls.peerCertificateChain 已声明的契约
// 对齐（「每个返回的证书是 owned，调用方负责 Close」）。
//
// wrapCertificate builds a Certificate from an underlying core certificate
// (package-private helper).
//
// It performs a DER round trip (MarshalDER → LoadCertificateDER), so the returned
// *Certificate **owns its handle** and the caller must Close it; the supplied c is
// unaffected.
//
// It stays package-private because the former exported
// WrapCertificate(c *core.Certificate) was the "internal/ type in a public
// signature" leak roadmap §5 E1 targets; out-of-package consumers now use
// internal/certaccess.Wrap (also a DER round trip).
//
// ⚠️ Semantic difference from the old entry point: WrapCertificate shared the
// handle (so Close released the true owner's object), whereas this produces an
// owned copy — matching the contract tls.peerCertificateChain already declared.
func wrapCertificate(c *core.Certificate) (*Certificate, error) {
	if c == nil {
		return nil, fmt.Errorf("x509: nil certificate handle")
	}
	der, err := c.MarshalDER()
	if err != nil {
		return nil, err
	}
	return LoadCertificateDER(der)
}

// MarshalPEM 导出证书为 PEM。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// MarshalPEM encodes the certificate in PEM format.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) MarshalPEM() ([]byte, error) {
	return c.cert.MarshalPEM()
}

// Subject 返回主题的 CN（Common Name）。
//
// Subject returns the Common Name (CN) of the certificate subject.
func (c *Certificate) Subject() string { return c.cert.Subject() }

// Issuer 返回签发者的 CN（Common Name）。
//
// Issuer returns the Common Name (CN) of the certificate issuer.
func (c *Certificate) Issuer() string { return c.cert.Issuer() }

// NotBefore 返回生效时间。
//
// NotBefore returns the certificate's activation time.
func (c *Certificate) NotBefore() time.Time { return c.cert.NotBefore() }

// NotAfter 返回过期时间。
//
// NotAfter returns the certificate's expiration time.
func (c *Certificate) NotAfter() time.Time { return c.cert.NotAfter() }

// Serial 返回证书序列号。
//
// Serial returns the certificate's serial number.
func (c *Certificate) Serial() int64 { return c.cert.Serial() }

// SerialHex 返回证书序列号的大写十六进制文本（不含 "serial=" 与 0x 前缀）。
//
// 序列号可能超出 int64 范围（如 openssl rand -hex 生成的 20 字节值），此时应改用
// 本方法而非 Serial；对齐 `openssl x509 -serial` 的取值格式。已关闭的证书返回空串。
//
// SerialHex returns the certificate serial number as uppercase hexadecimal
// without the "serial=" or 0x prefix.
//
// The serial number may exceed the int64 range (for example a 20-byte value
// from `openssl rand -hex`), in which case this method should be used instead
// of Serial. The format matches `openssl x509 -serial`. A closed certificate
// yields "".
func (c *Certificate) SerialHex() string { return c.cert.SerialHex() }

// SubjectHash 返回证书 subject 名字的 X509_NAME_hash。
//
// 对应 `openssl x509 -subject_hash`，也是 CA 目录中 hash.N 文件名里的那个 hash；
// 已关闭的证书返回 0。
//
// SubjectHash returns the X509_NAME_hash of the certificate's subject name.
//
// It corresponds to `openssl x509 -subject_hash`, which is also the hash used
// in a CA directory's hash.N file names. A closed certificate yields 0.
func (c *Certificate) SubjectHash() uint32 { return c.cert.SubjectHash() }

// IssuerHash 返回证书 issuer 名字的 X509_NAME_hash。
//
// 对应 `openssl x509 -issuer_hash`；已关闭的证书返回 0。
//
// IssuerHash returns the X509_NAME_hash of the certificate's issuer name.
//
// It corresponds to `openssl x509 -issuer_hash`. A closed certificate yields 0.
func (c *Certificate) IssuerHash() uint32 { return c.cert.IssuerHash() }

// Version 返回证书版本（0=v1，2=v3）。
//
// Version returns the certificate version field (0 = v1, 2 = v3).
func (c *Certificate) Version() int { return c.cert.Version() }

// SubjectName 返回主题的完整名字（含全部 RDN 条目，可配合 Entries/Get/String 使用）。
//
// SubjectName returns the full subject name containing all RDN entries; inspect it with Entries, Get, or String.
func (c *Certificate) SubjectName() *Name { return &Name{name: c.cert.SubjectName()} }

// IssuerName 返回签发者的完整名字（含全部 RDN 条目）。
//
// IssuerName returns the full issuer name containing all RDN entries; inspect it with Entries, Get, or String.
func (c *Certificate) IssuerName() *Name { return &Name{name: c.cert.IssuerName()} }

// SubjectEntries 返回主题的完整 RDN 条目。
//
// SubjectEntries returns every RDN entry of the subject in the order they appear in the certificate.
func (c *Certificate) SubjectEntries() []NameEntry {
	return convertEntries(c.cert.SubjectEntries())
}

// IssuerEntries 返回签发者的完整 RDN 条目。
//
// IssuerEntries returns every RDN entry of the issuer in the order they appear in the certificate.
func (c *Certificate) IssuerEntries() []NameEntry {
	return convertEntries(c.cert.IssuerEntries())
}

// SubjectText 返回主题完整 RDN 单行文本。
//
// SubjectText returns the subject's full RDN sequence as a single-line string.
func (c *Certificate) SubjectText() string { return c.cert.SubjectText() }

// IssuerText 返回签发者完整 RDN 单行文本。
//
// IssuerText returns the issuer's full RDN sequence as a single-line string.
func (c *Certificate) IssuerText() string { return c.cert.IssuerText() }

// SAN 返回证书 SAN（subjectAltName）扩展条目（如 "DNS:example.com"、"IP:1.2.3.4"）；
// 无 SAN 扩展返回 nil。
//
// SAN returns the certificate's subjectAltName entries (for example "DNS:example.com", "IP:1.2.3.4"). It returns nil when no SAN extension is present.
func (c *Certificate) SAN() []string { return c.cert.SAN() }

// KeyUsage 返回证书 KeyUsage 能力位名称列表（如 ["digitalSignature"]）；无则 nil。
//
// KeyUsage returns the certificate's KeyUsage bit names (for example ["digitalSignature"]). It returns nil when no KeyUsage extension is present.
//
// 位→名称映射遵循 RFC 5280 §4.2.1.3（固定的 9 位）：位序低→高依次为
// digitalSignature、nonRepudiation、keyEncipherment、dataEncipherment、
// keyAgreement、keyCertSign、cRLSign、encipherOnly、decipherOnly。位图来自
// core.Certificate.KeyUsageBits。
//
// The bit-to-name mapping follows RFC 5280 §4.2.1.3 (nine fixed bits):
// digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment,
// keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly (least to
// most significant). The bitmask comes from core.Certificate.KeyUsageBits.
func (c *Certificate) KeyUsage() []string {
	bits := c.cert.KeyUsageBits()
	if bits == 0 {
		return nil
	}
	out := make([]string, 0, 9)
	for b, name := range keyUsageNames {
		if bits&(1<<uint(b)) != 0 {
			out = append(out, name)
		}
	}
	return out
}

// keyUsageNames 为 RFC 5280 §4.2.1.3 KeyUsage 位（0–8）到短名的映射，
// 与 openssl x509 -text 输出一致。
//
// keyUsageNames maps the RFC 5280 §4.2.1.3 KeyUsage bits (0-8) to their
// short names, matching the human-readable form of `openssl x509 -text`.
var keyUsageNames = [...]string{
	"digitalSignature",
	"nonRepudiation",
	"keyEncipherment",
	"dataEncipherment",
	"keyAgreement",
	"keyCertSign",
	"cRLSign",
	"encipherOnly",
	"decipherOnly",
}

// ExtendedKeyUsage 返回证书 EKU 条目（如 ["serverAuth"]）；无则 nil。
//
// ExtendedKeyUsage returns the certificate's ExtendedKeyUsage entries (for example ["serverAuth"]). It returns nil when no EKU extension is present.
func (c *Certificate) ExtendedKeyUsage() []string { return c.cert.ExtendedKeyUsage() }

// IsCA 报告证书是否为 CA（BasicConstraints.CA=TRUE）。
//
// IsCA reports whether the certificate is a CA per BasicConstraints.CA = TRUE.
func (c *Certificate) IsCA() bool { return c.cert.IsCA() }

// PathLen 返回 CA 路径长度约束；无 pathlen 或非 CA 返回 -1。
//
// PathLen returns the CA path-length constraint, or -1 when pathlen is absent or the certificate is not a CA.
func (c *Certificate) PathLen() int64 { return c.cert.PathLen() }

// SubjectKeyID 返回 subjectKeyIdentifier 扩展字节；无则 nil。
//
// SubjectKeyID returns the bytes of the subjectKeyIdentifier extension, or nil when the extension is absent.
func (c *Certificate) SubjectKeyID() []byte { return c.cert.SubjectKeyID() }

// AuthorityKeyID 返回 authorityKeyIdentifier 中 keyid 字节；无则 nil。
//
// AuthorityKeyID returns the keyid bytes of the authorityKeyIdentifier extension, or nil when the extension is absent.
func (c *Certificate) AuthorityKeyID() []byte { return c.cert.AuthorityKeyID() }

// CertificateType 返回证书公钥算法名（如 "SM2"、"RSA"、"EC"）。
//
// CertificateType returns the algorithm name of the certificate's public key (for example "SM2", "RSA", "EC").
func (c *Certificate) CertificateType() string { return c.cert.CertificateType() }

// Extension 表示证书/CSR 中的一个 X.509 扩展。
//
// Nid 为扩展 NID；Field、OID 与 Critical 在读取时填充；
// Value 为构建时使用的 X509V3_EXT_conf 配置串；
// Data 为 DER 编码的扩展值（读取时填充）。
//
// Extension represents a single X.509 extension on a certificate or CSR.
//
// Nid is the extension NID. Field, OID and Critical are populated on read.
// Value holds an X509V3_EXT_conf configuration string used while building.
// Data holds the DER-encoded extension value (populated on read).
type Extension struct {
	Nid      int    // 扩展 NID
	Field    string // 扩展短名（读取时填充，如 "subjectAltName"）
	OID      string // 扩展点分 OID（读取时填充，如 "2.5.29.17"；OBJ_obj2txt(_,_,_,1)）
	Critical bool   // critical 标志（读取时填充）
	Value    string // X509V3_EXT_conf 配置串（构建时使用，如 "DNS:example.com"）
	Data     []byte // DER 编码的扩展值（读取时填充）
}

// Extensions 返回证书的全部扩展（按出现顺序）。
//
// Extensions returns all certificate extensions in the order they appear.
func (c *Certificate) Extensions() []Extension { return convertExtensions(c.cert.Extensions()) }

// AddSubjectAltName 添加 SAN 扩展（如 "DNS:example.com,IP:1.2.3.4"；须在 Sign 之前调用）。
//
// ⚠️ subjectAltName 属于可重复 OID：重复调用会把新值**合并**进同一条目
// （等价于把两次调用的值用逗号拼接后一次写入），而不是产生第二个扩展条目。
// 因此多次调用与一次传入 "DNS:a,DNS:b" 结果相同。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddSubjectAltName appends a subjectAltName extension (for example "DNS:example.com,IP:1.2.3.4"). It must be called before Sign.
//
// ⚠️ subjectAltName is a repeatable OID: repeated calls **merge** the new values
// into the single existing entry (equivalent to joining both calls' values with
// commas into one call) rather than producing a second extension entry. Calling
// it twice is therefore identical to a single call with "DNS:a,DNS:b".
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddSubjectAltName(value string) error {
	return c.cert.AddSubjectAltName(value)
}

// AddKeyUsage 添加 KeyUsage 扩展（如 "critical,digitalSignature,keyEncipherment"）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddKeyUsage appends a KeyUsage extension (for example "critical,digitalSignature,keyEncipherment").
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddKeyUsage(value string) error {
	return c.cert.AddKeyUsage(value)
}

// AddExtendedKeyUsage 添加 EKU 扩展（如 "serverAuth,clientAuth"）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddExtendedKeyUsage appends an ExtendedKeyUsage extension (for example "serverAuth,clientAuth").
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddExtendedKeyUsage(value string) error {
	return c.cert.AddExtendedKeyUsage(value)
}

// AddSubjectKeyID 添加 SKID 扩展（按主题公钥自动计算）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddSubjectKeyID appends a SubjectKeyIdentifier extension computed automatically from the subject's public key.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddSubjectKeyID() error {
	return c.cert.AddSubjectKeyID()
}

// AddAuthorityKeyID 添加 AKID 扩展（keyid 取自 issuer 证书的 SKID 或按 issuer 公钥计算）。
// 须在调用前为 issuer 完成公钥设置（推荐先对 issuer 调用 AddSubjectKeyID）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddAuthorityKeyID appends an AuthorityKeyIdentifier extension. The keyid is taken from the issuer's SKID when available, otherwise it is derived from the issuer's public key. The issuer must have its public key configured first; calling AddSubjectKeyID on the issuer before this is recommended.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddAuthorityKeyID(issuer *Certificate) error {
	if issuer == nil {
		return fmt.Errorf("x509: nil issuer certificate")
	}
	return c.cert.AddAuthorityKeyID(issuer.cert)
}

// AddExtension 按 NID 添加任意 X.509 扩展（如 NID 85 的 subjectAltName）。
//
// value 采用 OpenSSL X509V3_EXT_conf 配置语法（如 "DNS:example.com"、"critical,CA:TRUE"），
// 具体取值随扩展类型而定，详见 `openssl x509 -ext` 与 OpenSSL v3 扩展配置文档。
// 须在 Sign 之前调用；Sign 之后证书即不可变，再次调用返回错误。
//
// 同 NID 扩展已存在时：可重复 OID（subjectAltName / issuerAltName /
// subjectDirectoryAttributes / certificateIssuer）把新值**合并**进已有条目并保持原
// 位置与 critical 标记——OpenSSL 不接受同一证书内出现两个同 NID 条目，那会让
// SAN() 与 VerifyHostname() 全部失效；其余 OID 返回
// "x509: extension already present (nid N)"，需覆盖请改用 ReplaceExtension。
//
// raw 扩展（如 certificatePolicies / OID 2.5.29.32）同样可用，但其值语法由扩展
// 自身定义：内联形式为逗号分隔的策略 OID（如 "1.2.3.4"、"ia5org,1.2.3.4,1.5.6.7.8"）；
// 带 CPS / userNotice 限定符的 "@section" 形式**不支持**——本库不读取配置文件，
// 传入 "@polsect" 会被 OpenSSL 拒绝。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddExtension adds an arbitrary X.509 extension identified by nid (for example
// subjectAltName, NID 85).
//
// value uses the OpenSSL X509V3_EXT_conf configuration syntax (for example
// "DNS:example.com" or "critical,CA:TRUE"); the accepted values depend on the
// extension type, see `openssl x509 -ext` and the OpenSSL v3 extension
// configuration documentation. It must be called before Sign. Once the
// certificate is signed it becomes immutable and further calls return an error.
//
// When an extension with the same NID is already present, repeatable OIDs
// (subjectAltName / issuerAltName / subjectDirectoryAttributes /
// certificateIssuer) **merge** the new value into the existing entry, keeping
// its position and critical flag — OpenSSL rejects two entries with the same
// NID on one certificate, which would silently break both SAN() and
// VerifyHostname(). Every other OID returns
// "x509: extension already present (nid N)"; use ReplaceExtension to
// overwrite instead.
//
// raw extensions (such as certificatePolicies / OID 2.5.29.32) work as well, but
// their value syntax is defined by the extension itself: the inline form is a
// comma-separated list of policy OIDs (for example "1.2.3.4" or
// "ia5org,1.2.3.4,1.5.6.7.8"). The "@section" form carrying CPS / userNotice
// qualifiers is **not supported** — the library does not read configuration
// files, so passing "@polsect" is rejected by OpenSSL.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddExtension(nid int, value string) error {
	return c.cert.AddExtension(nid, value)
}

// AddExtensionByName 按名字添加任意 X.509 扩展。
//
// name 可为扩展短名（"keyUsage"、"extendedKeyUsage"、"subjectDirectoryAttributes"）、
// 长名或点分 OID（"2.5.29.15"），内部经 OBJ_txt2nid 解析，无需事先知道 NID 数值；
// name 为空或无法识别时返回 "x509: unknown extension name %q"。
// value 语法与 AddExtension 完全一致；重复检测与 Sign 后不可变规则同 AddExtension。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddExtensionByName adds an arbitrary X.509 extension addressed by name.
//
// name may be an extension short name ("keyUsage", "extendedKeyUsage",
// "subjectDirectoryAttributes"), a long name, or a dotted OID ("2.5.29.15");
// it is resolved through OBJ_txt2nid so callers need not know the numeric
// NID. An empty or unrecognized name returns
// "x509: unknown extension name %q".
//
// The value syntax is identical to AddExtension, and duplicate detection and
// the post-Sign immutability rule behave the same way.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddExtensionByName(name, value string) error {
	return c.cert.AddExtensionByName(name, value)
}

// AddExtensions 批量添加多个扩展（如 SAN + KeyUsage + EKU）。
//
// nil 或空切片为 no-op，返回 nil。每个 Extension 只使用 Nid 与 Value 两个字段
// （Field / OID / Critical / Data 为读取态，构建时忽略）。
// 按顺序逐条追加，中途失败时已追加的扩展会保留——调用方应丢弃该证书重建，
// 不得在不确定状态下继续签发。须在 Sign 之前调用。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddExtensions adds several extensions at once (for example SAN, KeyUsage and
// EKU).
//
// A nil or empty slice is a no-op and returns nil. Only the Nid and Value fields
// of each Extension are used; Field, OID, Critical and Data are populated on
// read and ignored here.
//
// The extensions are appended in order. When the call fails partway through,
// the extensions already appended are kept, so the caller must discard the
// certificate and rebuild rather than issuing it in an indeterminate state.
// It must be called before Sign.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddExtensions(exts ...Extension) error {
	cexts := make([]core.Extension, 0, len(exts))
	for _, e := range exts {
		cexts = append(cexts, core.Extension{Nid: e.Nid, Value: e.Value})
	}
	return c.cert.AddExtensions(cexts...)
}

// HasExtension 报告证书是否已包含 name 指定的扩展。
//
// name 为扩展短名、长名或点分 OID；未知名字与 nil / 已关闭证书均返回 false。
// 本方法只读不改，已签名证书可安全调用。用于在 AddExtension 前判断是否已存在，
// 或在验证证书结构时检查某个扩展的缺失。
//
// HasExtension reports whether the certificate already carries the extension
// identified by name.
//
// name may be a short name, a long name, or a dotted OID. An unknown name and a
// nil or closed certificate both yield false.
//
// The call never mutates the certificate, so it is safe on signed ones. Use it
// to check for presence before AddExtension, or to assert that an expected
// extension is present.
func (c *Certificate) HasExtension(name string) bool {
	return c.cert.HasExtension(name)
}

// RemoveExtension 删除 name 指定的扩展。
//
// name 为扩展短名、长名或点分 OID；未知名字返回 "x509: unknown extension name %q"，
// 证书中不存在该扩展返回 "x509: extension not present (nid N)"。
// ⚠️ 删除会改变证书 DER 字节，因此**必须在 Sign 之前调用**；若证书已签名，
// 删除操作会被拒绝（返回 "x509: certificate already signed"），
// 以免产出签名与内容不一致的证书。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// RemoveExtension removes the extension identified by name.
//
// An unknown name returns "x509: unknown extension name %q"; a name the
// certificate does not carry returns "x509: extension not present (nid N)".
//
// ⚠️ Removing an extension changes the DER encoding of the certificate, so it
// **must** be called before Sign. On an already signed certificate the call is
// rejected with "x509: certificate already signed" rather than producing a
// certificate whose signature no longer matches its content.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) RemoveExtension(name string) error {
	return c.cert.RemoveExtension(name)
}

// ReplaceExtension 覆盖 name 指定的扩展，并保持它在证书中的原有位置。
//
// 语义与 BouncyCastle X509ExtensionsGenerator.ReplaceExtension 一致：扩展不存在时
// 返回 "x509: extension not present (nid N)"，而不是替调用方新建。
// value 语法与 AddExtension 一致；须在 Sign 之前调用。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// ReplaceExtension overwrites the extension identified by name while keeping
// its original position in the certificate.
//
// The semantics match BouncyCastle's X509ExtensionsGenerator.ReplaceExtension:
// when the extension is absent the call returns
// "x509: extension not present (nid N)" instead of creating it on the caller's
// behalf. The value syntax matches AddExtension, and it must be called before
// Sign.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) ReplaceExtension(name, value string) error {
	return c.cert.ReplaceExtension(name, value)
}

// Fingerprint 计算证书指纹（十六进制小写）。
// alg 支持 "sha1"、"sha256"、"sm3"、"md5"、"sha384"、"sha512"。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// Fingerprint computes the certificate's fingerprint as a lowercase hexadecimal string. The alg parameter accepts "sha1", "sha256", "sm3", "md5", "sha384", and "sha512".
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) Fingerprint(alg string) (string, error) {
	var md *core.Digest
	switch strings.ToLower(alg) {
	case "sha1":
		md = core.SHA1()
	case "sha256":
		md = core.SHA256()
	case "sm3":
		md = core.SM3()
	case "md5":
		md = core.MD5()
	case "sha384":
		md = core.SHA384()
	case "sha512":
		md = core.SHA512()
	default:
		return "", fmt.Errorf("x509: unsupported fingerprint algorithm %q", alg)
	}
	return c.cert.Fingerprint(md)
}

// MarshalDER 导出证书为 DER 编码。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// MarshalDER encodes the certificate in DER format.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) MarshalDER() ([]byte, error) {
	return c.cert.MarshalDER()
}

// NewCertificate 创建一个空证书（构建用）。
// 通过 Set* 方法配置字段后调用 Sign 完成签名；CreateCertificate 是一次性便捷版。
//
// NewCertificate creates an empty certificate for incremental construction. Configure it with the Set* methods and call Sign to finalize; CreateCertificate is a one-shot equivalent.
func NewCertificate() *Certificate {
	cert, err := core.NewCertificate()
	if err != nil {
		panic(err)
	}
	return &Certificate{cert: cert}
}

// SetVersion 设置证书版本（0=v1，2=v3）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetVersion sets the certificate version (0 = v1, 2 = v3).
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SetVersion(v int) error { return c.cert.SetVersion(v) }

// SetSerial 设置证书序列号。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetSerial sets the certificate serial number.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SetSerial(serial int64) error { return c.cert.SetSerial(serial) }

// SetIssuer 设置签发者名字。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetIssuer sets the issuer name.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SetIssuer(n *Name) error { return c.cert.SetIssuer(n.name) }

// SetSubject 设置主题名字。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetSubject sets the subject name.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SetSubject(n *Name) error { return c.cert.SetSubject(n.name) }

// SetValidity 设置有效期。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetValidity sets the certificate validity window.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SetValidity(notBefore, notAfter time.Time) error {
	return c.cert.SetValidity(notBefore, notAfter)
}

// SetPublicKey 设置证书公钥（支持 SM2 / RSA / ECDSA 等 asym 包提供的算法）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetPublicKey sets the certificate public key (any algorithm the asym package
// provides, such as SM2 / RSA / ECDSA).
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SetPublicKey(pub asym.PublicKey) error {
	k, err := corePublicKey(pub)
	if err != nil {
		return err
	}
	return c.cert.SetPublicKey(k)
}

// AddBasicConstraints 添加 BasicConstraints 扩展（必须在 Sign 之前调用）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddBasicConstraints appends a BasicConstraints extension and must be called before Sign.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddBasicConstraints(isCA bool) error {
	return c.cert.AddBasicConstraints(isCA)
}

// Sign 使用签名私钥对证书签名（须先配置好版本/序列号/主题/签发者/有效期/公钥/扩展）。
// signer 支持 asym 包提供的算法，摘要按密钥类型自动选择。
//
// ⚠️ Sign 是单向终态：成功后证书不可变，任何 Set* / Add* / 再次 Sign 调用均返回
// "x509: certificate already signed"。这避免了「改了字段或扩展却忘了重签」而静默
// 产出签名失效的证书；确需修改请丢弃证书重建。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// Sign signs the certificate with signer after version, serial, subject, issuer, validity, public key, and extensions have been configured. signer may be any algorithm the asym package provides, and the digest is chosen automatically based on the key type.
//
// ⚠️ Sign is a one-way transition: on success the certificate becomes immutable
// and every later Set*, Add* or repeated Sign call returns
// "x509: certificate already signed". This prevents silently emitting a
// certificate whose signature no longer covers the modified content; discard
// the certificate and rebuild when changes are needed.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) Sign(signer asym.PrivateKey) error {
	k, err := corePrivateKey(signer)
	if err != nil {
		return err
	}
	return c.cert.Sign(k, nil)
}

// PublicKey 返回证书公钥，以 asym.PublicKey 呈现（适用任意算法）。
//
// 返回的对象**拥有**自己的底层句柄，使用完毕应调用 asym.Close 释放；不要依赖
// finalizer（AGENTS.md §4.4）。本方法取代了原 `PublicKey()`（返回 SM2 包装）与
// `PublicKeyPKey()`（返回底层原生句柄）两个入口（roadmap §5 E1-9），公开签名中不再
// 出现 internal/ 类型。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// PublicKey returns the certificate public key as an asym.PublicKey, which works
// for any algorithm.
//
// The returned value **owns** its underlying handle and should be released with
// asym.Close rather than relying on finalizers (AGENTS.md §4.4). It replaces the
// former `PublicKey()` (which returned an SM2 wrapper) and `PublicKeyPKey()`
// (which returned the raw native handle) (roadmap §5, E1-9), and no public
// signature mentions an internal/ type any more.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) PublicKey() (asym.PublicKey, error) {
	k, err := c.cert.PublicKey()
	if err != nil {
		return nil, err
	}
	// 句柄用完即弃：wrapCorePublicKey 走 PEM 往返，asym 侧得到的是独立对象。
	defer func() { _ = k.Close() }()
	return wrapCorePublicKey(k)
}

// VerifyHostname 校验证书是否对给定主机名或 IP 地址有效（对应
// `openssl verify -verify_hostname`）。
//
// host 为 IP 文本（IPv4 点分 / IPv6 冒号）时只比对 SAN 的 iPAddress 条目；否则先
// 比对 SAN 的 dNSName 条目，无 SAN 时回退比对 subject CN，并允许通配符
// （`*.example.com`）。
//
// ⚠️ 本函数只做「名字匹配」，**不**验证证书链、有效期或用途；客户端的正确顺序是
// 先 ChainVerify 建立信任，再调用本函数。对任意自签证书，本函数都可能返回 nil。
//
// 匹配返回 nil；不匹配返回描述性错误；host 为空返回 "x509: empty hostname"。
//
// VerifyHostname checks whether the certificate is valid for the given host
// name or IP address (equivalent to `openssl verify -verify_hostname`).
//
// When host is an IP literal (dotted IPv4 or colon IPv6) only the iPAddress
// SAN entries are compared; otherwise the dNSName SAN entries are compared
// first, falling back to the subject CN when no SAN is present, with
// wildcards such as `*.example.com` allowed.
//
// ⚠️ This performs name matching only. It does **not** validate the chain, the
// validity window or the key usage; the correct client-side order is to
// establish trust with ChainVerify first and then call this. For any
// self-signed certificate it may return nil.
//
// A match returns nil; a mismatch returns a descriptive error; an empty host
// returns "x509: empty hostname".
func (c *Certificate) VerifyHostname(host string) error {
	if c == nil || c.cert == nil {
		return fmt.Errorf("x509: nil certificate")
	}
	return c.cert.VerifyHostname(host)
}

// CheckEmail 校验证书是否对给定邮箱地址有效（对应 SAN 的 rfc822Name 条目）。
//
// ⚠️ 本函数只做「邮箱名字匹配」，**不**验证证书链、有效期或用途；客户端的正确顺序是
// 先 ChainVerify 建立信任，再调用本函数。对任意自签证书，本函数都可能返回 nil。
//
// 匹配返回 nil；不匹配返回描述性错误；email 为空或格式非法返回描述性错误；
// 已关闭的证书返回 "x509: invalid certificate"。
//
// CheckEmail checks whether the certificate is valid for the given e-mail
// address (matching a rfc822Name SAN entry).
//
// ⚠️ This performs name matching only. It does **not** validate the chain, the
// validity window or the key usage; the correct client-side order is to
// establish trust with ChainVerify first and then call this. For any
// self-signed certificate it may return nil.
//
// A match returns nil; a mismatch, an empty address and a malformed address
// return descriptive errors; a closed certificate returns
// "x509: invalid certificate".
func (c *Certificate) CheckEmail(email string) error {
	return c.cert.CheckEmail(email)
}

// Verify 使用签发者公钥验证证书签名。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// Verify checks the certificate signature against signerPub.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) Verify(signerPub asym.PublicKey) error {
	k, err := corePublicKey(signerPub)
	if err != nil {
		return err
	}
	return c.cert.Verify(k)
}

// SelfSigned 报告证书是否为自签（主题与签发者名字完全一致，且签名可被自身公钥验证通过）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SelfSigned reports whether the certificate is self-signed (subject and issuer names match exactly, and the signature verifies against the certificate's own public key).
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SelfSigned() (bool, error) {
	if c == nil {
		return false, fmt.Errorf("x509: nil certificate")
	}
	if c.SubjectText() != c.IssuerText() {
		return false, nil
	}
	pub, err := c.PublicKey()
	if err != nil {
		return false, err
	}
	if err := c.Verify(pub); err != nil {
		// 签名不通过：仍视为"主题/签发者同名"但非真正自签，返回 false 且无错误。
		return false, nil
	}
	return true, nil
}

// Signature 返回证书的原始签名字节（DER 编码）；证书无效或未签名返回 nil。
//
// Signature returns the certificate's raw signature bytes (DER-encoded), or nil when the certificate is invalid or has no signature.
func (c *Certificate) Signature() []byte { return c.cert.Signature() }

// SignatureAlgorithm 返回证书签名算法的短名（如 "SM2-SM3"、"RSA-SHA256"、"ecdsa-with-SHA256"）；不可识别返回 ""。
//
// SignatureAlgorithm returns the signature algorithm short name (for example "SM2-SM3", "RSA-SHA256", or "ecdsa-with-SHA256"), or "" when the algorithm is not recognized.
func (c *Certificate) SignatureAlgorithm() string { return c.cert.SignatureAlgorithm() }

// SignatureAlgorithmOID 返回证书签名算法的 OID 点分文本（如 "1.2.156.10197.1.501"、"1.2.840.113549.1.1.11"）；不可读取返回 ""。
//
// SignatureAlgorithmOID returns the signature algorithm OID as a dotted string (for example "1.2.156.10197.1.501" for SM2-with-SM3 or "1.2.840.113549.1.1.11" for sha256WithRSAEncryption), or "" when the OID cannot be read.
func (c *Certificate) SignatureAlgorithmOID() string { return c.cert.SignatureAlgorithmOID() }

// 窄接口 `PublicKey` / `PrivateKey` 已删除（roadmap §5 E1-11）：公开签名一律直接
// 用 `asym.PublicKey` / `asym.PrivateKey`，跨包取底层句柄经 `internal/keyaccess`
// （见 helpers.go 的 corePublicKey / corePrivateKey / wrapCorePublicKey）。
//
// The narrow PublicKey / PrivateKey interfaces were removed (roadmap §5, E1-11):
// public signatures now use asym.PublicKey / asym.PrivateKey directly, and
// cross-package handle access goes through internal/keyaccess (see corePublicKey /
// corePrivateKey / wrapCorePublicKey in helpers.go).

// CreateCertificate 创建一张由 signer 签发的证书。
// subject 为主题；issuer 为签发者（自签时与 subject 相同）；serial 为序列号；
// notBefore/notAfter 为有效期；pub 为证书公钥；signer 为签发私钥
// （自签时与 pub 对应，CA 签发时为 CA 私钥）。pub/signer 为 asym 包提供的密钥。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// CreateCertificate builds and signs a certificate with signer. subject is the subject name; issuer is the issuer name (use the same value as subject for a self-signed certificate); serial is the certificate serial number; notBefore and notAfter define the validity window; pub is the certificate public key; signer is the issuer private key (paired with pub for self-signed certificates, or the CA key when issued by a CA). pub and signer are asym package keys.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func CreateCertificate(subject, issuer *Name, serial int64, notBefore, notAfter time.Time,
	pub asym.PublicKey, signer asym.PrivateKey) (ret *Certificate, retErr error) {
	pubKey, err := corePublicKey(pub)
	if err != nil {
		return nil, err
	}
	signKey, err := corePrivateKey(signer)
	if err != nil {
		return nil, err
	}
	if subject == nil || issuer == nil {
		return nil, fmt.Errorf("x509: nil parameter")
	}
	cert, err := core.NewCertificate()
	if err != nil {
		return nil, err
	}
	// 任何中间步骤失败都要释放已创建的原生对象，避免泄漏（依赖 finalizer 兜底）。
	defer func() {
		if retErr != nil {
			_ = cert.Close()
		}
	}()
	if err := cert.SetVersion(2); err != nil { // v3
		return nil, err
	}
	if err := cert.SetSerial(serial); err != nil {
		return nil, err
	}
	if err := cert.SetIssuer(issuer.name); err != nil {
		return nil, err
	}
	if err := cert.SetSubject(subject.name); err != nil {
		return nil, err
	}
	if err := cert.SetValidity(notBefore, notAfter); err != nil {
		return nil, err
	}
	if err := cert.SetPublicKey(pubKey); err != nil {
		return nil, err
	}
	if err := cert.Sign(signKey, nil); err != nil { // nil → 按密钥类型自动选摘要
		return nil, err
	}
	return &Certificate{cert: cert}, nil
}

// PublicKey/PrivateKey 窄接口已删除（roadmap §5 E1-11）：公开签名一律直接用
// asym.PublicKey / asym.PrivateKey，跨包取底层句柄经 internal/keyaccess（见
// helpers.go 的 corePublicKey / corePrivateKey）。
//
// The narrow PublicKey / PrivateKey interfaces were removed (roadmap §5, E1-11):
// public signatures now use asym.PublicKey / asym.PrivateKey directly, and
// cross-package handle access goes through internal/keyaccess (see corePublicKey
// / corePrivateKey in helpers.go).

// CreateSelfSigned 一步生成自签证书（等价于 `openssl req -x509`）。
// subject 同时作为主题与签发者；serial 为序列号；notBefore/notAfter 为有效期；
// pub 为证书公钥；signer 为签名私钥（自签时与 pub 配对）。
//
// 与 CreateCertificate 的差异：
//   - issuer 自动取 subject（无需重复传参）；
//   - 自动补 subjectKeyIdentifier 与 authorityKeyIdentifier（后者取自自身的 SKID）；
//   - pub / signer 使用 asym 接口（而非已弃用的 x509.PublicKey / PrivateKey
//     窄接口），跨包取底层句柄经 internal/keyaccess，仅在调用期间短暂借用，
//     因此无需 Dup（Dup 只针对「取出来继续持有」的场景；X509_set_pubkey 内部
//     up-ref，X509_sign 在调用内用完即弃）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作；任何中间步骤
// 失败都会释放已创建的原生对象。
//
// CreateSelfSigned builds a self-signed certificate in one call (the equivalent of
// `openssl req -x509`). subject doubles as both subject and issuer; serial is the
// serial number; notBefore and notAfter define the validity window; pub is the
// certificate public key and signer the paired signing key.
//
// It differs from CreateCertificate in that the issuer is taken from subject
// automatically, the subjectKeyIdentifier and authorityKeyIdentifier extensions are
// added for you (the latter derived from the certificate's own SKID), and pub /
// signer use the asym interfaces rather than the deprecated x509.PublicKey /
// x509.PrivateKey narrow interfaces. The underlying handle is obtained through
// internal/keyaccess and only borrowed for the duration of the call, so no Dup is
// needed: the Dup rule covers handles extracted for later use, whereas
// X509_set_pubkey up-refs internally and X509_sign consumes the key only within the
// call.
//
// On failure it returns an error wrapping an OpError describing the operation, and
// any partially built native object is released.
func CreateSelfSigned(subject *Name, serial int64, notBefore, notAfter time.Time,
	pub asym.PublicKey, signer asym.PrivateKey) (ret *Certificate, retErr error) {
	if subject == nil || pub == nil || signer == nil {
		return nil, fmt.Errorf("x509: nil parameter")
	}
	pubKey, err := corePublicKey(pub)
	if err != nil {
		return nil, err
	}
	signKey, err := corePrivateKey(signer)
	if err != nil {
		return nil, err
	}
	cert, err := core.NewCertificate()
	if err != nil {
		return nil, err
	}
	// 任何中间步骤失败都要释放已创建的原生对象，避免泄漏（依赖 finalizer 兜底）。
	defer func() {
		if retErr != nil {
			_ = cert.Close()
		}
	}()
	if err := cert.SetVersion(2); err != nil { // v3
		return nil, err
	}
	if err := cert.SetSerial(serial); err != nil {
		return nil, err
	}
	// 自签：issuer == subject
	if err := cert.SetIssuer(subject.name); err != nil {
		return nil, err
	}
	if err := cert.SetSubject(subject.name); err != nil {
		return nil, err
	}
	if err := cert.SetValidity(notBefore, notAfter); err != nil {
		return nil, err
	}
	if err := cert.SetPublicKey(pubKey); err != nil {
		return nil, err
	}
	// SKID 需先于 AKID：AKID 取签发者（此处即自身）的 SKID。
	if err := cert.AddSubjectKeyID(); err != nil {
		return nil, err
	}
	if err := cert.AddAuthorityKeyID(cert); err != nil {
		return nil, err
	}
	if err := cert.Sign(signKey, nil); err != nil { // nil → 按密钥类型自动选摘要
		return nil, err
	}
	return &Certificate{cert: cert}, nil
}
