package x509

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// CertificateRequest 表示一个证书签名请求。
type CertificateRequest struct {
	req *core.CertificateRequest
}

// NewCertificateRequest 创建 CSR 并签名。
// subject 为主题；pub 为请求者公钥；priv 为请求者私钥（用于签名），支持 SM2 / RSA / ECDSA。
func NewCertificateRequest(subject *Name, pub PublicKey, priv PrivateKey) (*CertificateRequest, error) {
	if subject == nil || pub == nil || priv == nil {
		return nil, fmt.Errorf("x509: nil parameter")
	}
	req, err := core.NewCertificateRequest()
	if err != nil {
		return nil, err
	}
	if err := req.SetSubject(subject.name); err != nil {
		return nil, err
	}
	if err := req.SetPublicKey(pub.Key()); err != nil {
		return nil, err
	}
	if err := req.Sign(priv.Key(), nil); err != nil { // nil → 按密钥类型自动选摘要
		return nil, err
	}
	return &CertificateRequest{req: req}, nil
}

// NewEmptyCertificateRequest 创建空 CSR（构建用）。
// 通过 SetSubject / SetPublicKey / SetChallengePassword / AddExtensions 配置后调用 Sign 完成签名；
// NewCertificateRequest 是一次性便捷版（立即签名）。
func NewEmptyCertificateRequest() *CertificateRequest {
	r, err := core.NewCertificateRequest()
	if err != nil {
		panic(err)
	}
	return &CertificateRequest{req: r}
}

// SetSubject 设置 CSR 主题。
func (r *CertificateRequest) SetSubject(n *Name) error {
	if n == nil {
		return fmt.Errorf("x509: nil subject name")
	}
	return r.req.SetSubject(n.name)
}

// SetPublicKey 设置 CSR 公钥（支持 SM2 / RSA / ECDSA）。
func (r *CertificateRequest) SetPublicKey(pub PublicKey) error {
	if pub == nil {
		return fmt.Errorf("x509: nil public key")
	}
	return r.req.SetPublicKey(pub.Key())
}

// Sign 使用请求者私钥对 CSR 签名（须先配置好主题/公钥/扩展/口令）。
// priv 支持 SM2 / RSA / ECDSA，摘要按密钥类型自动选择。
func (r *CertificateRequest) Sign(priv PrivateKey) error {
	if priv == nil {
		return fmt.Errorf("x509: nil private key")
	}
	return r.req.Sign(priv.Key(), nil)
}

// LoadCertificateRequestPEM 从 PEM 加载 CSR。
func LoadCertificateRequestPEM(pemBytes []byte) (*CertificateRequest, error) {
	r, err := core.LoadCertificateRequestPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return &CertificateRequest{req: r}, nil
}

// LoadCertificateRequestDER 从 DER 编码加载 CSR。
func LoadCertificateRequestDER(der []byte) (*CertificateRequest, error) {
	r, err := core.LoadCertificateRequestDER(der)
	if err != nil {
		return nil, err
	}
	return &CertificateRequest{req: r}, nil
}

// MarshalPEM 导出 CSR 为 PEM。
func (r *CertificateRequest) MarshalPEM() ([]byte, error) {
	return r.req.MarshalPEM()
}

// Verify 使用 CSR 自身公钥验证签名。
func (r *CertificateRequest) Verify() error {
	return r.req.Verify()
}

// PublicKey 返回 CSR 公钥（SM2）。
func (r *CertificateRequest) PublicKey() (*sm2.PublicKey, error) {
	k, err := r.req.PublicKey()
	if err != nil {
		return nil, err
	}
	return sm2.PublicKeyFromPKey(k), nil
}

// SubjectName 返回 CSR 主题的完整名字（含全部 RDN 条目）。
func (r *CertificateRequest) SubjectName() *Name {
	return &Name{name: r.req.SubjectName()}
}

// SetChallengePassword 设置 CSR 挑战密码（PKCS#9 challengePassword 属性，须在 Sign 之前调用）。
func (r *CertificateRequest) SetChallengePassword(pwd string) error {
	return r.req.SetChallengePassword(pwd)
}

// ChallengePassword 返回 CSR 挑战密码；未设置返回空串。
func (r *CertificateRequest) ChallengePassword() string {
	return r.req.ChallengePassword()
}

// AddExtensions 为 CSR 添加多个扩展（如 SAN / KeyUsage / EKU，须在 Sign 之前调用）。
func (r *CertificateRequest) AddExtensions(exts ...Extension) error {
	cexts := make([]core.Extension, 0, len(exts))
	for _, e := range exts {
		cexts = append(cexts, core.Extension{Nid: e.Nid, Value: e.Value})
	}
	return r.req.AddExtensions(cexts...)
}

// AddExtension 为 CSR 添加单个扩展（如 "subjectAltName"，须在 Sign 之前调用）。
func (r *CertificateRequest) AddExtension(nid int, value string) error {
	return r.req.AddExtension(nid, value)
}

// AddSubjectAltName 为 CSR 添加 SAN 扩展（如 "DNS:example.com"）。
func (r *CertificateRequest) AddSubjectAltName(value string) error {
	return r.req.AddSubjectAltName(value)
}

// Extensions 返回 CSR 中的扩展列表（来自 extensionRequest 属性）。
func (r *CertificateRequest) Extensions() []Extension {
	return convertExtensions(r.req.Extensions())
}

// MarshalDER 导出 CSR 为 DER 编码。
func (r *CertificateRequest) MarshalDER() ([]byte, error) {
	return r.req.MarshalDER()
}
