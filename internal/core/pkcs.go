package core

import (
	"fmt"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// MemBIO 表示可读写的内存 BIO。
type MemBIO struct {
	bio unsafe.Pointer
}

// NewMemBIO 创建内存 BIO。
func NewMemBIO() (*MemBIO, error) {
	b := native.BIO_new(native.BIO_s_mem())
	if b == nil {
		return nil, NewOpError("bio: BIO_new(BIO_s_mem)", native.PopError())
	}
	return &MemBIO{bio: b}, nil
}

// Write 写入数据。
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
func (m *MemBIO) Bytes() ([]byte, error) {
	if m == nil || m.bio == nil {
		return nil, fmt.Errorf("bio: closed")
	}
	return readAllBIO(m.bio)
}

// Close 释放 BIO。
func (m *MemBIO) Close() {
	if m != nil && m.bio != nil {
		native.BIO_free(m.bio)
		m.bio = nil
	}
}

// PKCS12 表示 PKCS#12 容器（X.509 证书 + 私钥 + CA 链，.p12/.pfx）。
type PKCS12 struct {
	handle *Handle
}

// CreatePKCS12 打包证书、私钥与 CA 链为 PKCS12。
// pass 为口令；name 为友好名称（可空）；key 为私钥；cert 为主证书；ca 为 CA 链。
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
func LoadPKCS12DER(der []byte) (*PKCS12, error) {
	p := native.D2i_PKCS12(der)
	if p == nil {
		return nil, NewOpError("pkcs12: d2i_PKCS12", native.PopError())
	}
	return &PKCS12{handle: NewHandle(p, true, native.PKCS12_free)}, nil
}

// MarshalDER 导出 PKCS12 为 DER。
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
func (p *PKCS12) Close() error {
	if p == nil {
		return nil
	}
	return p.handle.Close()
}

// PKCS7 表示 PKCS#7 容器（SignedData，用于证书集合 / P7B 交换）。
type PKCS7 struct {
	handle *Handle
}

// NewPKCS7SignedData 创建空的 SignedData 类型 PKCS7（可 AddCertificate）。
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
func LoadPKCS7DER(der []byte) (*PKCS7, error) {
	p := native.D2i_PKCS7(der)
	if p == nil {
		return nil, NewOpError("pkcs7: d2i_PKCS7", native.PopError())
	}
	return &PKCS7{handle: NewHandle(p, true, native.PKCS7_free)}, nil
}

// MarshalDER 导出 PKCS7 为 DER。
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
func (p *PKCS7) Close() error {
	if p == nil {
		return nil
	}
	return p.handle.Close()
}
