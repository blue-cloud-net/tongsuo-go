package x509

import (
	"errors"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Store 表示证书信任存储，作为 ChainVerify 的信任锚。
type Store struct {
	store *core.Store
}

// NewStore 创建空的信任存储。
func NewStore() *Store {
	s, err := core.NewStore()
	if err != nil {
		panic(err)
	}
	return &Store{store: s}
}

// Core 返回底层核心信任存储（供内部跨包使用，如 ocsp）。
func (s *Store) Core() *core.Store { return s.store }

// AddCert 向存储添加信任证书（如 Root CA 证书）。
func (s *Store) AddCert(c *Certificate) error {
	if c == nil {
		return fmt.Errorf("x509: nil certificate")
	}
	return s.store.AddCert(c.cert)
}

// AddCRL 向存储添加 CRL（配合 SetCRLCheck / SetCRLCheckAll 启用吊销检查）。
func (s *Store) AddCRL(c *CRL) error {
	if c == nil {
		return fmt.Errorf("x509: nil CRL")
	}
	return s.store.AddCRL(c.crl)
}

// SetCRLCheck 启用 CRL 吊销检查（仅检查叶证书所在链）。
func (s *Store) SetCRLCheck() error {
	return s.store.SetFlags(0x4)
}

// SetCRLCheckAll 启用全链 CRL 吊销检查（检查链上所有证书）。
func (s *Store) SetCRLCheckAll() error {
	return s.store.SetFlags(0x8)
}

// VerifyError 表示证书链验证失败详情。
type VerifyError struct {
	Code    int    // X509_V_ERR_* 错误码（如 10=certificate has expired）
	Depth   int    // 出错深度（0 为待验证证书本身）
	Message string // 错误描述
}

// Error 实现 error 接口。
func (e *VerifyError) Error() string {
	return fmt.Sprintf("x509: certificate verify failed: %s (code=%d, depth=%d)",
		e.Message, e.Code, e.Depth)
}

// ChainVerify 验证证书链并返回构建的完整链（索引 0 为叶证书，末位为根）。
// roots 为信任锚存储（含 Root CA）；intermediates 为中间证书（用于补全链，可省略）。
// 验证失败返回 *VerifyError。
func ChainVerify(cert *Certificate, roots *Store, intermediates []*Certificate) ([]*Certificate, error) {
	if cert == nil {
		return nil, fmt.Errorf("x509: nil certificate")
	}
	if roots == nil {
		return nil, fmt.Errorf("x509: nil trust store")
	}
	ccerts := make([]*core.Certificate, 0, len(intermediates))
	for _, ic := range intermediates {
		if ic == nil {
			return nil, fmt.Errorf("x509: nil intermediate certificate")
		}
		ccerts = append(ccerts, ic.cert)
	}
	chain, err := core.ChainVerify(cert.cert, roots.store, ccerts)
	if err != nil {
		var ve *core.VerifyError
		if errors.As(err, &ve) {
			return nil, &VerifyError{Code: ve.Code, Depth: ve.Depth, Message: ve.Message}
		}
		return nil, err
	}
	out := make([]*Certificate, 0, len(chain))
	for _, c := range chain {
		out = append(out, &Certificate{cert: c})
	}
	return out, nil
}
