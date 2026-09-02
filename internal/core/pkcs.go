package core

import (
	"fmt"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// MemBIO 表示可读写的内存 BIO。
// 类型拥有底层 BIO 指针，使用完毕须调用 Close 释放。
//
// MemBIO is a thin wrapper around an in-memory OpenSSL BIO (BIO_s_mem)
// that supports both writing and reading.
type MemBIO struct {
	bio unsafe.Pointer
}

// NewMemBIO 创建内存 BIO。
// 返回的 *MemBIO 拥有底层 BIO 指针，使用完毕须调用 Close 释放。
//
// NewMemBIO creates a fresh empty in-memory BIO.
func NewMemBIO() (*MemBIO, error) {
	b := native.BIO_new(native.BIO_s_mem())
	if b == nil {
		return nil, NewOpError("bio: BIO_new(BIO_s_mem)", native.PopError())
	}
	return &MemBIO{bio: b}, nil
}

// Write 写入数据。
//
// Write appends data to the BIO.
//
// A nil data slice is a no-op and returns nil; otherwise the call returns
// the error "bio: closed" if the BIO has been closed, or a wrapped
// OpError when BIO_write reports a short write.
func (m *MemBIO) Write(data []byte) error {
	if m == nil || m.bio == nil {
		return fmt.Errorf("bio: closed")
	}
	if len(data) > 0 && native.BIO_write(m.bio, data) != len(data) {
		return NewOpError("bio: BIO_write", native.PopError())
	}
	return nil
}

// Bytes 读取全部内容（读取后内部读指针移至末尾）。
//
// Bytes reads the entire content of the BIO and advances the internal
// read pointer to the end.
//
// After this call, subsequent Bytes invocations return an empty slice
// (unless more data is written in the meantime). Returns the error
// "bio: closed" when the BIO has been closed, or "x509: empty BIO
// output" when the BIO contains no data.
func (m *MemBIO) Bytes() ([]byte, error) {
	if m == nil || m.bio == nil {
		return nil, fmt.Errorf("bio: closed")
	}
	return readAllBIO(m.bio)
}

// Close 释放 BIO。
//
// Close releases the underlying BIO pointer.
//
// The call is idempotent: invoking it on a nil receiver or on an
// already-closed *MemBIO does nothing further. After Close returns, any
// other method on the same *MemBIO returns the error "bio: closed", so
// the caller must guarantee that no concurrent goroutine still holds a
// reference to this BIO.
func (m *MemBIO) Close() {
	if m != nil && m.bio != nil {
		native.BIO_free(m.bio)
		m.bio = nil
	}
}

// PKCS12 表示 PKCS#12 容器（X.509 证书 + 私钥 + CA 链，.p12/.pfx）。
// 类型拥有底层 PKCS12 句柄（通过内部 Handle），使用完毕须调用 Close 释放。
//
// PKCS12 is the Go wrapper around an OpenSSL PKCS#12 container holding
// an X.509 certificate, a private key and an optional CA chain (the
// .p12 / .pfx file format).
type PKCS12 struct {
	handle *Handle
}

// CreatePKCS12 打包证书、私钥与 CA 链为 PKCS12。
// pass 为口令；name 为友好名称（可空）；key 为私钥；cert 为主证书；ca 为 CA 链。
//
// ca 中为 nil 或已关闭的元素会被静默跳过，因此空切片生成不含额外中间 CA 的容器。
//
// 底层 PKCS12_create 调用失败时返回包装为 OpError 的错误。
//
// CreatePKCS12 packages a private key, an end-entity certificate and an
// optional CA chain into a PKCS#12 container.
//
// pass is the integrity / encryption password, name is the friendlyName
// attribute (may be empty), key is the private key and cert is the main
// certificate; nil or closed elements of the ca slice are silently
// skipped, so an empty slice produces a container without extra
// intermediate CAs.
//
// Errors from the underlying PKCS12_create call are wrapped as OpError.
func CreatePKCS12(pass, name string, key *PKey, cert *Certificate, ca []*Certificate) (*PKCS12, error) {
	if key == nil || key.handle == nil || key.handle.IsClosed() {
		return nil, fmt.Errorf("pkcs12: invalid private key")
	}
	if cert == nil || cert.handle == nil || cert.handle.IsClosed() {
		return nil, fmt.Errorf("pkcs12: invalid certificate")
	}
	caPtrs := make([]unsafe.Pointer, 0, len(ca))
	for _, c := range ca {
		if c != nil && c.handle != nil && !c.handle.IsClosed() {
			caPtrs = append(caPtrs, c.handle.Ptr())
		}
	}
	p := native.X_PKCS12_create(pass, name, key.handle.Ptr(), cert.handle.Ptr(), caPtrs)
	if p == nil {
		return nil, NewOpError("pkcs12: PKCS12_create", native.PopError())
	}
	return &PKCS12{handle: NewHandle(p, true, native.PKCS12_free)}, nil
}

// LoadPKCS12DER 从 DER 加载 PKCS12。
// 返回的 *PKCS12 拥有底层句柄，使用完毕须调用 Close 释放；失败时返回包装为 OpError 的错误。
//
// LoadPKCS12DER parses an ASN.1 DER-encoded PKCS#12 container.
func LoadPKCS12DER(der []byte) (*PKCS12, error) {
	p := native.D2i_PKCS12(der)
	if p == nil {
		return nil, NewOpError("pkcs12: d2i_PKCS12", native.PopError())
	}
	return &PKCS12{handle: NewHandle(p, true, native.PKCS12_free)}, nil
}

// MarshalDER 导出 PKCS12 为 DER。
//
// MarshalDER serializes the PKCS#12 container to its ASN.1 DER encoding.
//
// Returns an error when the container has been closed via Close, or when
// the underlying i2d_PKCS12 call fails (wrapped as OpError).
func (p *PKCS12) MarshalDER() ([]byte, error) {
	if p == nil || p.handle == nil || p.handle.IsClosed() {
		return nil, fmt.Errorf("pkcs12: closed")
	}
	der, ok := native.I2d_PKCS12(p.handle.Ptr())
	if !ok {
		return nil, NewOpError("pkcs12: i2d_PKCS12", native.PopError())
	}
	return der, nil
}

// Parse 解析出私钥、主证书与 CA 链。
//
// Parse extracts the private key, end-entity certificate and CA chain
// from the PKCS#12 container.
//
// pass must match the password used during CreatePKCS12; an incorrect
// password surfaces as a wrapped OpError containing the OpenSSL error
// code. The returned *PKey and *Certificate are fresh references owned
// by the caller (each must be closed individually); each entry of the
// CA chain is also an independent *Certificate that must be closed. The
// CA chain may be empty when the container does not embed intermediates.
// Returns "pkcs12: closed" if the container has been closed via Close.
func (p *PKCS12) Parse(pass string) (*PKey, *Certificate, []*Certificate, error) {
	if p == nil || p.handle == nil || p.handle.IsClosed() {
		return nil, nil, nil, fmt.Errorf("pkcs12: closed")
	}
	pkey, cert, caSk, ok := native.X_PKCS12_parse(p.handle.Ptr(), pass)
	if !ok {
		return nil, nil, nil, NewOpError("pkcs12: PKCS12_parse", native.PopError())
	}
	var key *PKey
	if pkey != nil {
		key = &PKey{handle: NewHandle(pkey, true, native.EVP_PKEY_free)}
	}
	var c *Certificate
	if cert != nil {
		c = &Certificate{handle: NewHandle(cert, true, native.X509_free)}
	}
	var chain []*Certificate
	if caSk != nil {
		defer native.X509_sk_X509_pop_free(caSk)
		count := native.X509_sk_X509_num(caSk)
		chain = make([]*Certificate, 0, count)
		for i := 0; i < count; i++ {
			x := native.X509_sk_X509_value(caSk, i)
			if x == nil {
				continue
			}
			// 复制后释放栈（栈元素归调用方所有）。
			dup := native.X509_dup(x)
			if dup == nil {
				continue
			}
			chain = append(chain, &Certificate{handle: NewHandle(dup, true, native.X509_free)})
		}
	}
	return key, c, chain, nil
}

// ChangePassword 修改 PKCS12 口令。
//
// ChangePassword re-encrypts the PKCS#12 container with a new password.
//
// oldPass must match the current password (otherwise the underlying
// PKCS12_newpass call fails and the error is wrapped as OpError);
// newPass becomes the new integrity / encryption password. The
// container must be live; otherwise the call returns "pkcs12: closed".
func (p *PKCS12) ChangePassword(oldPass, newPass string) error {
	if p == nil || p.handle == nil || p.handle.IsClosed() {
		return fmt.Errorf("pkcs12: closed")
	}
	if !native.PKCS12_newpass(p.handle.Ptr(), oldPass, newPass) {
		return NewOpError("pkcs12: PKCS12_newpass", native.PopError())
	}
	return nil
}

// SetMAC 为 PKCS12 重新计算 MAC（SHA-256）。
//
// SetMAC recomputes the integrity MAC of the PKCS#12 container using
// SHA-256 (the Tongsuo / OpenSSL default).
//
// pass is used to derive the MAC key and must match the current password
// for the MAC to verify. The container must be live; otherwise the call
// returns "pkcs12: closed". Errors from the underlying PKCS12_set_mac
// call are wrapped as OpError.
func (p *PKCS12) SetMAC(pass string) error {
	if p == nil || p.handle == nil || p.handle.IsClosed() {
		return fmt.Errorf("pkcs12: closed")
	}
	if !native.PKCS12_set_mac(p.handle.Ptr(), pass) {
		return NewOpError("pkcs12: PKCS12_set_mac", native.PopError())
	}
	return nil
}

// Close 释放 PKCS12。幂等。
//
// Close releases the underlying PKCS12 handle.
//
// The call is idempotent: invoking it on a nil receiver or on a
// container that has already been closed returns nil without further
// side effects. After Close returns, any other method on the same
// *PKCS12 returns the error "pkcs12: closed", so the caller must
// guarantee that no concurrent goroutine still holds a reference to
// this container.
func (p *PKCS12) Close() error {
	if p == nil {
		return nil
	}
	return p.handle.Close()
}

// PKCS7 表示 PKCS#7 容器（SignedData，用于证书集合 / P7B 交换）。
// 类型拥有底层 PKCS7 句柄（通过内部 Handle），使用完毕须调用 Close 释放。
//
// PKCS7 is the Go wrapper around an OpenSSL PKCS#7 container. The
// current implementation only supports the SignedData variant used for
// certificate-bundle exchange (P7B files).
type PKCS7 struct {
	handle *Handle
}

// NewPKCS7SignedData 创建空的 SignedData 类型 PKCS7（可 AddCertificate）。
//
// 内部调用 PKCS7_new 创建容器，使用 PKCS7_set_type 设定为 NID_pkcs7_signed，
// 并通过 PKCS7_content_new 初始化空的 NID_pkcs7_data 内容（NID_pkcs7_data == 21）。
//
// 返回的 *PKCS7 拥有底层句柄，使用完毕须调用 Close 释放。
//
// NewPKCS7SignedData creates an empty SignedData PKCS#7 container ready
// for AddCertificate calls.
//
// Internally the container is created via PKCS7_new, typed with
// NID_pkcs7_signed (PKCS7_set_type) and initialised with an empty
// NID_pkcs7_data content (NID_pkcs7_data == 21).
//
// The returned *PKCS7 owns the underlying handle and the caller must
// invoke Close to release it.
func NewPKCS7SignedData() (*PKCS7, error) {
	p := native.PKCS7_new()
	if p == nil {
		return nil, NewOpError("pkcs7: PKCS7_new", native.PopError())
	}
	h := NewHandle(p, true, native.PKCS7_free)
	if !native.PKCS7_set_type(p, native.NidPKCS7Signed) {
		_ = h.Close()
		return nil, NewOpError("pkcs7: PKCS7_set_type", native.PopError())
	}
	if !native.PKCS7_content_new(p, 21) { // NID_pkcs7_data = 21
		_ = h.Close()
		return nil, NewOpError("pkcs7: PKCS7_content_new", native.PopError())
	}
	return &PKCS7{handle: h}, nil
}

// AddCertificate 向 PKCS7 追加证书。
//
// AddCertificate appends a certificate to the SignedData container.
//
// Both p and c must be live, non-closed objects; otherwise the call
// returns "pkcs7: closed" or "pkcs7: invalid certificate". Errors from
// the underlying PKCS7_add_certificate call are wrapped as OpError.
func (p *PKCS7) AddCertificate(c *Certificate) error {
	if p == nil || p.handle == nil || p.handle.IsClosed() {
		return fmt.Errorf("pkcs7: closed")
	}
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return fmt.Errorf("pkcs7: invalid certificate")
	}
	if !native.PKCS7_add_certificate(p.handle.Ptr(), c.handle.Ptr()) {
		return NewOpError("pkcs7: PKCS7_add_certificate", native.PopError())
	}
	return nil
}

// LoadPKCS7DER 从 DER 加载 PKCS7。
// 返回的 *PKCS7 拥有底层句柄，使用完毕须调用 Close 释放；失败时返回包装为 OpError 的错误。
//
// LoadPKCS7DER parses an ASN.1 DER-encoded PKCS#7 container.
func LoadPKCS7DER(der []byte) (*PKCS7, error) {
	p := native.D2i_PKCS7(der)
	if p == nil {
		return nil, NewOpError("pkcs7: d2i_PKCS7", native.PopError())
	}
	return &PKCS7{handle: NewHandle(p, true, native.PKCS7_free)}, nil
}

// MarshalDER 导出 PKCS7 为 DER。
//
// MarshalDER serializes the PKCS#7 container to its ASN.1 DER encoding.
//
// Returns an error when the container has been closed via Close, or when
// the underlying i2d_PKCS7 call fails (wrapped as OpError).
func (p *PKCS7) MarshalDER() ([]byte, error) {
	if p == nil || p.handle == nil || p.handle.IsClosed() {
		return nil, fmt.Errorf("pkcs7: closed")
	}
	der, ok := native.I2d_PKCS7(p.handle.Ptr())
	if !ok {
		return nil, NewOpError("pkcs7: i2d_PKCS7", native.PopError())
	}
	return der, nil
}

// Certificates 提取 PKCS7 中的证书（复制）。
//
// Certificates returns the certificates embedded in the PKCS#7 container
// as fresh, independent copies.
//
// Each *Certificate in the returned slice owns its X509 reference and
// the caller must close them individually. Returns "pkcs7: closed" if
// the container has been closed via Close, or nil (with a nil error)
// when the container has no certificate stack.
func (p *PKCS7) Certificates() ([]*Certificate, error) {
	if p == nil || p.handle == nil || p.handle.IsClosed() {
		return nil, fmt.Errorf("pkcs7: closed")
	}
	sk := native.PKCS7_get0_certificates(p.handle.Ptr())
	if sk == nil {
		return nil, nil
	}
	count := native.X509_sk_X509_num(sk)
	out := make([]*Certificate, 0, count)
	for i := 0; i < count; i++ {
		x := native.X509_sk_X509_value(sk, i)
		if x == nil {
			continue
		}
		dup := native.X509_dup(x)
		if dup == nil {
			continue
		}
		out = append(out, &Certificate{handle: NewHandle(dup, true, native.X509_free)})
	}
	return out, nil
}

// Close 释放 PKCS7。幂等。
//
// Close releases the underlying PKCS7 handle.
//
// The call is idempotent: invoking it on a nil receiver or on a
// container that has already been closed returns nil without further
// side effects. After Close returns, any other method on the same
// *PKCS7 returns the error "pkcs7: closed", so the caller must
// guarantee that no concurrent goroutine still holds a reference to
// this container.
func (p *PKCS7) Close() error {
	if p == nil {
		return nil
	}
	return p.handle.Close()
}
