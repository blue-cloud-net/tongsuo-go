package pkcs7

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/certaccess"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/keyaccess"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// SignOptions 配置 PKCS#7 签名；输入证书与密钥归调用方持有。
//
// SignOptions configures PKCS#7 signing; callers retain input certificates and keys.
type SignOptions struct {
	// SignerCert 为必填签名证书。
	//
	// SignerCert is the required signing certificate.
	SignerCert *x509.Certificate
	// SignerKey 为对应私钥；8.4 基线支持 RSA/ECDSA。
	//
	// SignerKey is the matching private key; the 8.4 baseline supports RSA/ECDSA.
	SignerKey asym.PrivateKey
	// ExtraCerts 为随签名携带的补充证书，不自动成为信任锚。
	//
	// ExtraCerts carries additional certificates without making them trust anchors.
	ExtraCerts []*x509.Certificate
	// Digest 默认 SHA-256，必须为铜锁支持的签名摘要。
	//
	// Digest defaults to SHA-256 and must be a Tongsuo-supported signature digest.
	Digest string
	// Detached 为 true 时分离内容，否则携带内容。
	//
	// Detached omits content when true; otherwise content is attached.
	Detached bool
}

// VerifyOptions 配置全部签名者及证书信任验证；默认必须给出 Roots。
//
// VerifyOptions configures verification of every signer and its trust; Roots is required by default.
type VerifyOptions struct {
	// Roots 是显式信任锚；仅 SignatureOnly 为 true 时可省略。
	//
	// Roots contains explicit trust anchors and may be omitted only in SignatureOnly mode.
	Roots *x509.Store
	// ExtraCerts 为外部签名者和补链证书，不自动受信任。
	//
	// ExtraCerts supplies external signer and intermediate certificates without trusting them.
	ExtraCerts []*x509.Certificate
	// DetachedContent 的 nil 表示未提供；非 nil 空切片表示分离的空内容。
	//
	// DetachedContent uses nil for absent content and a non-nil empty slice for empty detached content.
	DetachedContent []byte
	// SignatureOnly 显式跳过证书链验证，仍验证所有签名；结果不标为受信任。
	//
	// SignatureOnly explicitly skips chain validation while checking all signatures; results are not marked trusted.
	SignatureOnly bool
}

// EncryptOptions 配置多 RSA 接收者的 EnvelopedData；不提供完整性认证。
//
// EncryptOptions configures EnvelopedData for multiple RSA recipients without integrity authentication.
type EncryptOptions struct {
	// Recipients 为非空接收者证书列表，所有公钥须为 RSA。
	//
	// Recipients is a nonempty certificate list with RSA public keys.
	Recipients []*x509.Certificate
	// Cipher 默认 AES-256-CBC；支持 AES-128/192/256-CBC 及兼容 DES-EDE3-CBC。
	//
	// Cipher defaults to AES-256-CBC; AES-128/192/256-CBC and compatibility DES-EDE3-CBC are supported.
	Cipher string
}

// DecryptOptions 指定接收者证书和对应 RSA 私钥。
//
// DecryptOptions supplies a recipient certificate and matching RSA private key.
type DecryptOptions struct {
	// RecipientCert 标识信封接收者。
	//
	// RecipientCert identifies the envelope recipient.
	RecipientCert *x509.Certificate
	// RecipientKey 是对应的 RSA 私钥。
	//
	// RecipientKey is the matching RSA private key.
	RecipientKey asym.PrivateKey
}

// SignedData 保存验证后的内容和签名者；调用方须 Close 释放证书，并负责清零敏感内容。
//
// SignedData holds verified content and signers; callers must Close certificates and zero sensitive content.
type SignedData struct {
	// Content 为全部要求验证成功后的原始内容。
	//
	// Content is the original content after all required verification succeeds.
	Content []byte
	// Signers 为独立持有的签名者证书，由 Close 释放。
	//
	// Signers contains independently owned signer certificates released by Close.
	Signers []*x509.Certificate
	// TrustVerified 仅在全部签名者通过显式信任验证后为 true。
	//
	// TrustVerified is true only after every signer passes explicit trust verification.
	TrustVerified bool
}

// Close 幂等释放签名者证书，保留内容；不得与使用返回证书并发调用。
//
// Close idempotently releases signer certificates and retains content; do not race it with certificate use.
func (s *SignedData) Close() error {
	if s == nil {
		return nil
	}
	for _, cert := range s.Signers {
		if err := cert.Close(); err != nil {
			return err
		}
	}
	s.Signers = nil
	return nil
}

func operationDER(data []byte) ([]byte, error) {
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "PKCS7" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("pkcs7: invalid PKCS7 PEM")
		}
		data = block.Bytes
	}
	var raw stdasn1.RawValue
	rest, err := stdasn1.Unmarshal(data, &raw)
	if err != nil || len(rest) != 0 || raw.Class != 0 || raw.Tag != 16 || !raw.IsCompound {
		return nil, fmt.Errorf("pkcs7: invalid DER")
	}
	return data, nil
}
func operationCertificates(certs []*x509.Certificate) ([]*core.Certificate, error) {
	result := make([]*core.Certificate, 0, len(certs))
	for _, cert := range certs {
		h, err := coreCertOf(cert)
		if err != nil {
			return nil, err
		}
		result = append(result, h)
	}
	return result, nil
}
func operationKey(key asym.PrivateKey) (*core.PKey, error) {
	if key == nil {
		return nil, fmt.Errorf("pkcs7: nil private key")
	}
	h, ok := keyaccess.PKey(key)
	if !ok || h == nil {
		return nil, fmt.Errorf("pkcs7: unavailable private key")
	}
	return h.Dup()
}

// Sign 返回 PKCS#7 DER，默认 SHA-256 与附带二进制内容，不转换换行。
// 支持 RSA/ECDSA；参数不匹配及原生失败返回错误，调用方负责清零源切片。
//
// Sign returns PKCS#7 DER using SHA-256 and attached binary content by default, without newline conversion.
// RSA/ECDSA are supported; parameter mismatches and native failures return errors. Callers zero source slices.
func Sign(data []byte, opts *SignOptions) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("pkcs7: signing options required")
	}
	cert, err := coreCertOf(opts.SignerCert)
	if err != nil {
		return nil, err
	}
	key, err := operationKey(opts.SignerKey)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	extra, err := operationCertificates(opts.ExtraCerts)
	if err != nil {
		return nil, err
	}
	digest := opts.Digest
	if digest == "" {
		digest = "SHA256"
	}
	return core.SignPKCS7(data, cert, key, extra, digest, opts.Detached)
}

// Verify 验证 DER/PEM 中全部签名者，默认还验证其至显式 Roots 的证书链。
// SignatureOnly 显式仅验签，TrustVerified 为 false；失败不返回内容或部分结果。
// 返回值须 Close；分离内容缺失与非 nil 空内容不同，证书袋不算有效签名。
//
// Verify verifies every signer in DER/PEM and by default their chains to explicit Roots.
// Explicit SignatureOnly verifies signatures with TrustVerified false; failure returns no content or partial result.
// Close the result; absent detached content differs from non-nil empty content, and certificate-only bags are not signatures.
func Verify(data []byte, opts *VerifyOptions) (*SignedData, error) {
	if opts == nil {
		opts = &VerifyOptions{}
	}
	if !opts.SignatureOnly && opts.Roots == nil {
		return nil, fmt.Errorf("pkcs7: explicit trust store required")
	}
	der, err := operationDER(data)
	if err != nil {
		return nil, err
	}
	p, err := core.LoadPKCS7DER(der)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	extras, err := operationCertificates(opts.ExtraCerts)
	if err != nil {
		return nil, err
	}
	content, signers, err := p.VerifySignatures(opts.DetachedContent, extras)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, c := range signers {
			c.Close()
		}
	}()
	result := &SignedData{Content: content}
	success := false
	defer func() {
		if !success {
			result.Close()
		}
	}()
	for _, c := range signers {
		cert, err := certaccess.Wrap(c)
		if err != nil {
			return nil, err
		}
		result.Signers = append(result.Signers, cert)
	}
	if !opts.SignatureOnly {
		embedded, err := p.Certificates()
		if err != nil {
			return nil, err
		}
		defer func() {
			for _, c := range embedded {
				c.Close()
			}
		}()
		intermediates := append([]*x509.Certificate{}, opts.ExtraCerts...)
		var temporary []*x509.Certificate
		defer func() {
			for _, c := range temporary {
				c.Close()
			}
		}()
		for _, c := range embedded {
			cert, err := certaccess.Wrap(c)
			if err != nil {
				return nil, err
			}
			temporary = append(temporary, cert)
			intermediates = append(intermediates, cert)
		}
		for _, signer := range result.Signers {
			chain, err := x509.ChainVerify(signer, opts.Roots, intermediates)
			if err != nil {
				return nil, fmt.Errorf("pkcs7: signer trust: %w", err)
			}
			for _, c := range chain {
				c.Close()
			}
		}
		result.TrustVerified = true
	}
	success = true
	return result, nil
}

// Encrypt 生成多 RSA 接收者的 DER 信封，默认 AES-256-CBC，按二进制处理内容。
// CBC 不提供完整性认证；不支持的参数返回错误，调用方负责清零源切片。
//
// Encrypt creates binary DER envelopes for multiple RSA recipients, defaulting to AES-256-CBC.
// CBC provides no integrity authentication; unsupported parameters fail and callers zero source slices.
func Encrypt(data []byte, opts *EncryptOptions) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("pkcs7: encryption options required")
	}
	certs, err := operationCertificates(opts.Recipients)
	if err != nil {
		return nil, err
	}
	cipher := strings.ToUpper(opts.Cipher)
	if cipher == "" {
		cipher = "AES-256-CBC"
	}
	return core.EncryptPKCS7(data, certs, cipher)
}

// Decrypt 解密 DER/PEM 信封，失败不返回部分明文；调用方负责清零返回明文。
// 解密成功不代表内容经过完整性认证。
//
// Decrypt decrypts DER/PEM envelopes without partial plaintext on failure; callers zero returned plaintext.
// Successful decryption does not imply integrity authentication.
func Decrypt(data []byte, opts *DecryptOptions) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("pkcs7: decryption options required")
	}
	der, err := operationDER(data)
	if err != nil {
		return nil, err
	}
	cert, err := coreCertOf(opts.RecipientCert)
	if err != nil {
		return nil, err
	}
	key, err := operationKey(opts.RecipientKey)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	p, err := core.LoadPKCS7DER(der)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	return p.DecryptContent(cert, key)
}
