package core

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// Name 表示 X.509 名字（X509_NAME 的包装），用于构建证书主题/签发者。
type Name struct {
	handle *Handle
}

// NewName 创建空名字。
func NewName() (*Name, error) {
	n := native.X509_NAME_new()
	if n == nil {
		return nil, NewOpError("x509: X509_NAME_new", native.PopError())
	}
	return &Name{handle: NewHandle(n, true, native.X509_NAME_free)}, nil
}

// AddEntry 添加名字条目。field 取 "CN"、"C"、"O"、"OU"、"L"、"ST"、"serialNumber"、"emailAddress" 等。
func (n *Name) AddEntry(field, value string) error {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return fmt.Errorf("x509: name closed")
	}
	if !native.X509_NAME_add_entry_by_txt(n.handle.Ptr(), field, value) {
		return NewOpError("x509: X509_NAME_add_entry_by_txt", native.PopError())
	}
	return nil
}

// Text 返回名字中指定 NID 字段的文本（如 native.NidCommonName）。
func (n *Name) Text(nid int) string {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return ""
	}
	return native.X509_NAME_get_text_by_NID(n.handle.Ptr(), nid)
}

// Close 释放底层名字。幂等。
func (n *Name) Close() error {
	if n == nil {
		return nil
	}
	return n.handle.Close()
}

// Certificate 表示一张 X.509 证书（X509 的包装）。
type Certificate struct {
	handle *Handle
}

// NewCertificate 创建空的证书对象。
func NewCertificate() (*Certificate, error) {
	x := native.X509_new()
	if x == nil {
		return nil, NewOpError("x509: X509_new", native.PopError())
	}
	return &Certificate{handle: NewHandle(x, true, native.X509_free)}, nil
}

// LoadCertificatePEM 从 PEM 加载证书。
func LoadCertificatePEM(pem []byte) (*Certificate, error) {
	bio := native.BIO_new_mem_buf(pem)
	if bio == nil {
		return nil, NewOpError("x509: BIO_new_mem_buf", native.PopError())
	}
	defer native.BIO_free(bio)
	x := native.X_PEM_read_bio_X509(bio)
	if x == nil {
		return nil, NewOpError("x509: PEM_read_bio_X509", native.PopError())
	}
	return &Certificate{handle: NewHandle(x, true, native.X509_free)}, nil
}

// MarshalPEM 导出证书为 PEM。
func (c *Certificate) MarshalPEM() ([]byte, error) {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil, fmt.Errorf("x509: certificate closed")
	}
	bio := native.BIO_new(native.BIO_s_mem())
	if bio == nil {
		return nil, NewOpError("x509: BIO_new", native.PopError())
	}
	defer native.BIO_free(bio)
	if !native.X_PEM_write_bio_X509(bio, c.handle.Ptr()) {
		return nil, NewOpError("x509: PEM_write_bio_X509", native.PopError())
	}
	return readAllBIO(bio)
}

// SetVersion 设置证书版本（0=v1，2=v3）。
func (c *Certificate) SetVersion(version int) error {
	if !native.X509_set_version(c.handle.Ptr(), version) {
		return NewOpError("x509: X509_set_version", native.PopError())
	}
	return nil
}

// SetSerial 设置证书序列号。
func (c *Certificate) SetSerial(serial int64) error {
	if !native.X509_set_serial_int(c.handle.Ptr(), serial) {
		return NewOpError("x509: X509_set_serialNumber", native.PopError())
	}
	return nil
}

// SetIssuer 设置签发者名字。
func (c *Certificate) SetIssuer(n *Name) error {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return fmt.Errorf("x509: invalid issuer name")
	}
	if !native.X509_set_issuer_name(c.handle.Ptr(), n.handle.Ptr()) {
		return NewOpError("x509: X509_set_issuer_name", native.PopError())
	}
	return nil
}

// SetSubject 设置主题名字。
func (c *Certificate) SetSubject(n *Name) error {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return fmt.Errorf("x509: invalid subject name")
	}
	if !native.X509_set_subject_name(c.handle.Ptr(), n.handle.Ptr()) {
		return NewOpError("x509: X509_set_subject_name", native.PopError())
	}
	return nil
}

// SetPublicKey 设置证书公钥。
func (c *Certificate) SetPublicKey(k *PKey) error {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return fmt.Errorf("x509: invalid public key")
	}
	if !native.X509_set_pubkey(c.handle.Ptr(), k.handle.Ptr()) {
		return NewOpError("x509: X509_set_pubkey", native.PopError())
	}
	return nil
}

// SetValidity 设置有效期（生效/过期时间）。
func (c *Certificate) SetValidity(notBefore, notAfter time.Time) error {
	if !notAfter.After(notBefore) {
		return fmt.Errorf("x509: notAfter must be after notBefore")
	}
	if !native.X509_set_not_before(c.handle.Ptr(), notBefore.Unix()) {
		return NewOpError("x509: ASN1_TIME_set(notBefore)", native.PopError())
	}
	if !native.X509_set_not_after(c.handle.Ptr(), notAfter.Unix()) {
		return NewOpError("x509: ASN1_TIME_set(notAfter)", native.PopError())
	}
	return nil
}

// AddBasicConstraints 添加 BasicConstraints 扩展（必须在 Sign 之前调用）。
// isCA 为 true 时标记为 CA 证书（critical,CA:TRUE）。
func (c *Certificate) AddBasicConstraints(isCA bool) error {
	val := "critical,CA:FALSE"
	if isCA {
		val = "critical,CA:TRUE"
	}
	ext := native.X509V3_EXT_conf_nid(native.NidBasicConstraints, val)
	if ext == nil {
		return NewOpError("x509: X509V3_EXT_conf_nid(basicConstraints)", native.PopError())
	}
	defer native.X509_EXTENSION_free(ext)
	if !native.X509_add_ext(c.handle.Ptr(), ext) {
		return NewOpError("x509: X509_add_ext", native.PopError())
	}
	return nil
}

// Sign 使用签名私钥与摘要算法对证书签名（自签时签名密钥与公钥对应，CA 签发时用 CA 私钥）。
func (c *Certificate) Sign(signer *PKey, md *Digest) error {
	if signer == nil || signer.handle == nil || signer.handle.IsClosed() {
		return fmt.Errorf("x509: invalid signer")
	}
	if md == nil || md.handle == nil {
		return fmt.Errorf("x509: invalid digest")
	}
	if !native.X509_sign(c.handle.Ptr(), signer.handle.Ptr(), md.handle.Ptr()) {
		return NewOpError("x509: X509_sign", native.PopError())
	}
	return nil
}

// Verify 使用公钥验证证书签名。
func (c *Certificate) Verify(pub *PKey) error {
	if pub == nil || pub.handle == nil || pub.handle.IsClosed() {
		return fmt.Errorf("x509: invalid public key")
	}
	if !native.X509_verify(c.handle.Ptr(), pub.handle.Ptr()) {
		return NewOpError("x509: X509_verify", native.PopError())
	}
	return nil
}

// SubjectName 返回主题名字（内部指针，勿关闭）。
func (c *Certificate) SubjectName() *Name {
	n := native.X509_get_subject_name(c.handle.Ptr())
	if n == nil {
		return nil
	}
	return &Name{handle: NewHandle(n, false, nil)}
}

// IssuerName 返回签发者名字（内部指针，勿关闭）。
func (c *Certificate) IssuerName() *Name {
	n := native.X509_get_issuer_name(c.handle.Ptr())
	if n == nil {
		return nil
	}
	return &Name{handle: NewHandle(n, false, nil)}
}

// Subject 返回主题的 CN（Common Name）。
func (c *Certificate) Subject() string {
	n := c.SubjectName()
	if n == nil {
		return ""
	}
	return n.Text(native.NidCommonName)
}

// Issuer 返回签发者的 CN（Common Name）。
func (c *Certificate) Issuer() string {
	n := c.IssuerName()
	if n == nil {
		return ""
	}
	return n.Text(native.NidCommonName)
}

// NotBefore 返回生效时间。
func (c *Certificate) NotBefore() time.Time {
	return time.Unix(native.X509_get_not_before(c.handle.Ptr()), 0).UTC()
}

// NotAfter 返回过期时间。
func (c *Certificate) NotAfter() time.Time {
	return time.Unix(native.X509_get_not_after(c.handle.Ptr()), 0).UTC()
}

// Serial 返回证书序列号。
func (c *Certificate) Serial() int64 {
	return native.X509_get_serial_int(c.handle.Ptr())
}

// PublicKey 返回证书公钥（新引用，调用方负责释放）。
func (c *Certificate) PublicKey() (*PKey, error) {
	p := native.X509_get_pubkey(c.handle.Ptr())
	if p == nil {
		return nil, NewOpError("x509: X509_get_pubkey", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// Close 释放底层证书。幂等。
func (c *Certificate) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}

// CertificateRequest 表示一个证书签名请求（X509_REQ 的包装）。
type CertificateRequest struct {
	handle *Handle
}

// NewCertificateRequest 创建空的 CSR。
func NewCertificateRequest() (*CertificateRequest, error) {
	r := native.X509_REQ_new()
	if r == nil {
		return nil, NewOpError("x509: X509_REQ_new", native.PopError())
	}
	return &CertificateRequest{handle: NewHandle(r, true, native.X509_REQ_free)}, nil
}

// LoadCertificateRequestPEM 从 PEM 加载 CSR。
func LoadCertificateRequestPEM(pem []byte) (*CertificateRequest, error) {
	bio := native.BIO_new_mem_buf(pem)
	if bio == nil {
		return nil, NewOpError("x509: BIO_new_mem_buf", native.PopError())
	}
	defer native.BIO_free(bio)
	r := native.X_PEM_read_bio_X509_REQ(bio)
	if r == nil {
		return nil, NewOpError("x509: PEM_read_bio_X509_REQ", native.PopError())
	}
	return &CertificateRequest{handle: NewHandle(r, true, native.X509_REQ_free)}, nil
}

// MarshalPEM 导出 CSR 为 PEM。
func (r *CertificateRequest) MarshalPEM() ([]byte, error) {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return nil, fmt.Errorf("x509: request closed")
	}
	bio := native.BIO_new(native.BIO_s_mem())
	if bio == nil {
		return nil, NewOpError("x509: BIO_new", native.PopError())
	}
	defer native.BIO_free(bio)
	if !native.X_PEM_write_bio_X509_REQ(bio, r.handle.Ptr()) {
		return nil, NewOpError("x509: PEM_write_bio_X509_REQ", native.PopError())
	}
	return readAllBIO(bio)
}

// SetSubject 设置 CSR 主题。
func (r *CertificateRequest) SetSubject(n *Name) error {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return fmt.Errorf("x509: invalid subject name")
	}
	if !native.X509_REQ_set_subject_name(r.handle.Ptr(), n.handle.Ptr()) {
		return NewOpError("x509: X509_REQ_set_subject_name", native.PopError())
	}
	return nil
}

// SetPublicKey 设置 CSR 公钥。
func (r *CertificateRequest) SetPublicKey(k *PKey) error {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return fmt.Errorf("x509: invalid public key")
	}
	if !native.X509_REQ_set_pubkey(r.handle.Ptr(), k.handle.Ptr()) {
		return NewOpError("x509: X509_REQ_set_pubkey", native.PopError())
	}
	return nil
}

// Sign 使用请求者私钥对 CSR 签名。
func (r *CertificateRequest) Sign(priv *PKey, md *Digest) error {
	if priv == nil || priv.handle == nil || priv.handle.IsClosed() {
		return fmt.Errorf("x509: invalid private key")
	}
	if md == nil || md.handle == nil {
		return fmt.Errorf("x509: invalid digest")
	}
	if !native.X509_REQ_sign(r.handle.Ptr(), priv.handle.Ptr(), md.handle.Ptr()) {
		return NewOpError("x509: X509_REQ_sign", native.PopError())
	}
	return nil
}

// Verify 使用 CSR 自身公钥验证签名。
//
// 注意：Tongsuo 8.5-pre1 的 X509_REQ_verify 对 SM2 证书签名请求存在缺陷
// （返回 -1），故此处手动重建 CertificationRequestInfo 的 DER 并使用
// SM2 验签路径校验（结果与 openssl req -verify 一致）。
func (r *CertificateRequest) Verify() error {
	info, ok := native.I2d_X509_REQ_INFO(r.handle.Ptr())
	if !ok {
		return NewOpError("x509: i2d_X509_REQ_INFO", native.PopError())
	}
	sig, ok := native.X509_REQ_get0_signature(r.handle.Ptr())
	if !ok {
		return NewOpError("x509: X509_REQ_get0_signature", native.PopError())
	}
	pub := native.X509_REQ_get_pubkey(r.handle.Ptr())
	if pub == nil {
		return NewOpError("x509: X509_REQ_get_pubkey", native.PopError())
	}
	pkey := &PKey{handle: NewHandle(pub, true, native.EVP_PKEY_free)}
	defer pkey.Close()
	return pkey.Verify(info, sig, nil)
}

// PublicKey 返回 CSR 公钥（新引用，调用方负责释放）。
func (r *CertificateRequest) PublicKey() (*PKey, error) {
	p := native.X509_REQ_get_pubkey(r.handle.Ptr())
	if p == nil {
		return nil, NewOpError("x509: X509_REQ_get_pubkey", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// Close 释放底层 CSR。幂等。
func (r *CertificateRequest) Close() error {
	if r == nil {
		return nil
	}
	return r.handle.Close()
}

func readAllBIO(bio unsafe.Pointer) ([]byte, error) {
	var out []byte
	tmp := make([]byte, 1024)
	for {
		n := native.BIO_read(bio, tmp)
		if n <= 0 {
			break
		}
		out = append(out, tmp[:n]...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("x509: empty BIO output")
	}
	return out, nil
}
