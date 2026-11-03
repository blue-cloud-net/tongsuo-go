package core

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// AddTrust 添加信任或拒绝用途；已关闭证书返回错误。
//
// AddTrust adds a trusted or rejected purpose; closed certificates return errors.
func (c *Certificate) AddTrust(purpose string, reject bool) error {
	defer runtime.KeepAlive(c)
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return fmt.Errorf("x509: certificate closed")
	}
	if purpose == "" || strings.ContainsRune(purpose, 0) {
		return fmt.Errorf("x509: invalid trust purpose")
	}
	if !native.X_X509_add_trust(c.handle.Ptr(), purpose, reject) {
		return NewOpError("x509: add trust", native.PopError())
	}
	return nil
}

// ClearTrust 清空信任或拒绝用途；已关闭证书返回错误。
//
// ClearTrust clears trusted or rejected purposes; closed certificates return errors.
func (c *Certificate) ClearTrust(reject bool) error {
	defer runtime.KeepAlive(c)
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return fmt.Errorf("x509: certificate closed")
	}
	native.X_X509_clear_trust(c.handle.Ptr(), reject)
	return nil
}

// MarshalTrustedPEM 导出包含本地信任属性的 PEM；属性不在证书签名范围内。
//
// MarshalTrustedPEM exports PEM with local trust attributes, which are outside the certificate signature.
func (c *Certificate) MarshalTrustedPEM() ([]byte, error) {
	defer runtime.KeepAlive(c)
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil, fmt.Errorf("x509: certificate closed")
	}
	bio := native.BIO_new(native.BIO_s_mem())
	if bio == nil {
		return nil, NewOpError("x509: BIO_new", native.PopError())
	}
	defer native.BIO_free(bio)
	if !native.PEM_write_bio_X509_AUX(bio, c.handle.Ptr()) {
		return nil, NewOpError("x509: write trusted PEM", native.PopError())
	}
	return readAllBIO(bio)
}

// LoadTrustedCertificatePEM 加载普通或 TRUSTED CERTIFICATE PEM；调用方负责 Close。
//
// LoadTrustedCertificatePEM loads ordinary or TRUSTED CERTIFICATE PEM; callers must Close it.
func LoadTrustedCertificatePEM(data []byte) (*Certificate, error) {
	bio := native.BIO_new(native.BIO_s_mem())
	if bio == nil {
		return nil, NewOpError("x509: BIO_new", native.PopError())
	}
	defer native.BIO_free(bio)
	if len(data) > 0 && native.BIO_write(bio, data) != len(data) {
		return nil, NewOpError("BIO_write", native.PopError())
	}

	p := native.PEM_read_bio_X509_AUX(bio)
	if p == nil {
		return nil, NewOpError("x509: read trusted PEM", native.PopError())
	}
	return &Certificate{handle: NewHandle(p, true, native.X509_free), signed: true}, nil
}
