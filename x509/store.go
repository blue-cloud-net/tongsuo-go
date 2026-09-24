package x509

import (
	"errors"
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Store 表示证书信任存储，作为 ChainVerify 的信任锚。
//
// Store represents a trust store of certificates that serves as the trust anchor set for ChainVerify.
type Store struct {
	store *core.Store
}

// NewStore 创建空的信任存储。
//
// NewStore creates an empty trust store. Use AddCert to add trusted roots and AddCRL (paired with SetCRLCheck or SetCRLCheckAll) to enable revocation checking.
func NewStore() *Store {
	s, err := core.NewStore()
	if err != nil {
		panic(err)
	}
	return &Store{store: s}
}

// AddCert 向存储添加信任证书（如 Root CA 证书）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddCert adds a trusted certificate (typically a Root CA) to the store.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (s *Store) AddCert(c *Certificate) error {
	if c == nil {
		return fmt.Errorf("x509: nil certificate")
	}
	return s.store.AddCert(c.cert)
}

// AddCRL 向存储添加 CRL（配合 SetCRLCheck / SetCRLCheckAll 启用吊销检查）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddCRL adds a CRL to the store. Pair with SetCRLCheck or SetCRLCheckAll to enable revocation checking.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (s *Store) AddCRL(c *CRL) error {
	if c == nil {
		return fmt.Errorf("x509: nil CRL")
	}
	return s.store.AddCRL(c.crl)
}

// SetCRLCheck 启用 CRL 吊销检查（仅检查叶证书所在链）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetCRLCheck enables CRL revocation checking for the leaf certificate's chain only.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (s *Store) SetCRLCheck() error {
	return s.store.SetFlags(core.StoreFlagCRLCheck)
}

// SetCRLCheckAll 启用全链 CRL 吊销检查（检查链上所有证书）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetCRLCheckAll enables CRL revocation checking for every certificate in the chain.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (s *Store) SetCRLCheckAll() error {
	return s.store.SetFlags(core.StoreFlagCRLCheckAll)
}

// SetFlags 通用设置存储验证标志（位或组合）。
// 可用标志包括 native.X509VFlagCRLCheck / native.X509VFlagCRLCheckAll；
// 标志值取自 OpenSSL 的 X509_V_FLAG_*。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetFlags sets verification flags on the Store as a bitwise combination.
// Available flags include native.X509VFlagCRLCheck and
// native.X509VFlagCRLCheckAll (bit values match OpenSSL's X509_V_FLAG_*).
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (s *Store) SetFlags(flags uint64) error {
	return s.store.SetFlags(flags)
}

// SetTime 指定该信任存储的验证时刻（对应 `openssl verify -attime`）。
//
// 设置后对本存储上**后续每次** ChainVerify 都生效（不限于下一次调用），可反复
// 覆盖；典型用途是以固定历史时刻验证已过期 / 尚未生效的证书链。
//
// ⚠️ 安全提示：验证时刻回拨会让已过期的证书通过链验证。仅在确有必要时（离线复核
// 历史签名、验证归档数据）使用，不要用它掩盖真实的过期状态。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetTime sets the verification time of the store (equivalent to
// `openssl verify -attime`).
//
// Once set it affects **every subsequent** ChainVerify performed with this
// store (not just the next call) and may be overwritten repeatedly. The
// typical use is validating a chain as of a fixed historical instant, for
// certificates that have expired or are not yet valid.
//
// ⚠️ Security note: rolling the verification time back lets an expired
// certificate pass chain validation. Use it only when genuinely required
// (replaying a historical signature, validating archived data) and never to
// mask a real expiry.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (s *Store) SetTime(t time.Time) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("x509: nil store")
	}
	return s.store.SetTime(t)
}

// VerifyError 表示证书链验证失败详情。
//
// Code 为 X509_V_ERR_* 错误码（如 10 表示 "certificate has expired"）；
// Depth 为出错深度（0 为待验证证书本身）；
// Message 为人类可读的失败描述。
//
// VerifyError reports the details of a failed certificate chain verification.
//
// Code is the X509_V_ERR_* error code (for example 10 means "certificate has expired"),
// Depth is the failing depth (0 is the certificate being verified), and
// Message is a human-readable description of the failure.
type VerifyError struct {
	Code    int    // X509_V_ERR_* 错误码（如 10=certificate has expired）
	Depth   int    // 出错深度（0 为待验证证书本身）
	Message string // 错误描述
}

// Error 实现 error 接口。
//
// Error formats the VerifyError as a string and satisfies the error interface.
func (e *VerifyError) Error() string {
	return fmt.Sprintf("x509: certificate verify failed: %s (code=%d, depth=%d)",
		e.Message, e.Code, e.Depth)
}

// ChainVerify 验证证书链并返回构建的完整链（索引 0 为叶证书，末位为根）。
// roots 为信任锚存储（含 Root CA）；intermediates 为中间证书（用于补全链，可省略）。
// 验证失败返回 *VerifyError。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// ChainVerify verifies the certificate chain rooted at cert and returns the assembled chain with the leaf certificate at index 0 and the root at the end. roots is the trust anchor store containing trusted Root CAs; intermediates is an optional list of intermediate certificates used to complete the chain.
//
// On failure, it returns an error wrapping an OpError describing the operation.
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
