// Package pkcs7 基于铜锁原生实现实现 PKCS#7 容器（P7B 证书集合交换）。
// 提供证书集合的打包（Build）与提取（Extract），支持 DER 与 PEM（"BEGIN PKCS7"）。
//
// Package pkcs7 implements the PKCS#7 container (P7B certificate-bag) backed
// by the Tongsuo native library. It provides Build and Extract for certificate
// bundles; both DER and PEM ("BEGIN PKCS7") formats are supported.
package pkcs7

import (
	"bytes"
	"encoding/pem"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/certaccess"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	tx509 "github.com/blue-cloud-net/tongsuo-go/x509"
)

// coreCertOf 经 internal/certaccess 取出证书的底层 *core.Certificate 句柄。
//
// x509 已弃用 Certificate.Core()（roadmap §5 E1-8：公开签名中不得出现 internal/
// 类型），跨包取证书句柄统一走桥接包；取不到时返回错误。
//
// coreCertOf extracts the underlying *core.Certificate handle through
// internal/certaccess.
//
// x509 deprecated Certificate.Core() (roadmap §5, E1-8: no public signature may
// mention an internal/ type), so cross-package handle access goes through the
// bridge package. A failure returns an error.
func coreCertOf(c *tx509.Certificate) (*core.Certificate, error) {
	if c == nil {
		return nil, fmt.Errorf("pkcs7: nil certificate")
	}
	h, ok := certaccess.Certificate(c)
	if !ok || h == nil {
		return nil, fmt.Errorf("pkcs7: certificate handle unavailable")
	}
	return h, nil
}

// Build 构建包含证书集合的 PKCS#7（SignedData，无签名者，仅证书），返回 DER。
// certs 中的 nil 条目会被静默跳过。
//
// Build wraps a certificate bundle into a PKCS#7 SignedData structure
// (signer info empty, certificates only) and returns the DER encoding. nil
// entries in certs are silently skipped.
func Build(certs []*tx509.Certificate) ([]byte, error) {
	p7, err := core.NewPKCS7SignedData()
	if err != nil {
		return nil, err
	}
	defer p7.Close()
	for _, c := range certs {
		if c == nil {
			continue
		}
		h, err := coreCertOf(c)
		if err != nil {
			return nil, err
		}
		if err := p7.AddCertificate(h); err != nil {
			return nil, err
		}
	}
	return p7.MarshalDER()
}

// MarshalPEM 将 PKCS#7 DER 编码为 PEM（"BEGIN PKCS7"）。
//
// MarshalPEM re-encodes a PKCS#7 DER blob as PEM using the "PKCS7" type
// label (i.e. "-----BEGIN PKCS7-----").
func MarshalPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: der})
}

// FromCRL 把一组 CRL 打包为 PKCS#7（SignedData，无签名者，仅证书吊销列表），
// 返回 DER。对应铜锁 CLI 的 `crl2pkcs7 -nocrl -certfile ...` 中的 CRL 侧用法。
// crls 中的 nil 条目会被静默跳过。
//
// FromCRL packs a list of CRLs into a PKCS#7 SignedData structure (empty
// signer info, CRLs only) and returns the DER encoding — the CRL side of
// the Tongsuo CLI `crl2pkcs7`. nil entries in crls are silently skipped.
func FromCRL(crls []*tx509.CRL) ([]byte, error) {
	p7, err := core.NewPKCS7SignedData()
	if err != nil {
		return nil, err
	}
	defer p7.Close()
	for _, c := range crls {
		if c == nil {
			continue
		}
		der, err := c.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("pkcs7: crl: %w", err)
		}
		h, err := core.LoadCRLDER(der)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: crl: %w", err)
		}
		addErr := p7.AddCRL(h)
		_ = h.Close()
		if addErr != nil {
			return nil, addErr
		}
	}
	return p7.MarshalDER()
}

// ExtractCRLs 从 PKCS#7（DER 或 PEM）提取 CRL。
// 容器中没有 CRL 时返回空切片与 nil 错误。
//
// ExtractCRLs reads the CRLs out of a PKCS#7 container given as DER or PEM
// (with "BEGIN PKCS7" header). A container without CRLs yields an empty
// slice and a nil error.
func ExtractCRLs(data []byte) ([]*tx509.CRL, error) {
	der, err := decode(data)
	if err != nil {
		return nil, err
	}
	p7, err := core.LoadPKCS7DER(der)
	if err != nil {
		return nil, err
	}
	defer p7.Close()
	crls, err := p7.CRLs()
	if err != nil {
		return nil, err
	}
	out := make([]*tx509.CRL, 0, len(crls))
	for _, c := range crls {
		raw, merr := c.MarshalDER()
		_ = c.Close()
		if merr != nil {
			return nil, fmt.Errorf("pkcs7: crl: %w", merr)
		}
		wrapped, werr := tx509.ParseCRL(raw)
		if werr != nil {
			return nil, fmt.Errorf("pkcs7: crl: %w", werr)
		}
		out = append(out, wrapped)
	}
	return out, nil
}

// Extract 从 PKCS#7（DER 或 PEM）提取证书。
// 输入支持 DER 或 PEM（含 "BEGIN PKCS7" 头）；返回按叶到根顺序排列的
// *x509.Certificate 包装列表。
//
// Extract reads certificates out of a PKCS#7 container given as DER or PEM
// (with "BEGIN PKCS7" header); it returns the leaf-first list of
// *x509.Certificate wrappers.
func Extract(data []byte) ([]*tx509.Certificate, error) {
	der, err := decode(data)
	if err != nil {
		return nil, err
	}
	p7, err := core.LoadPKCS7DER(der)
	if err != nil {
		return nil, err
	}
	defer p7.Close()
	certs, err := p7.Certificates()
	if err != nil {
		return nil, err
	}
	out := make([]*tx509.Certificate, 0, len(certs))
	for _, c := range certs {
		wrapped, werr := certaccess.Wrap(c)
		if werr != nil {
			return nil, werr
		}
		out = append(out, wrapped)
	}
	return out, nil
}

// decode 自动识别 PEM / DER 并返回 DER。
//
// decode inspects the input and returns the DER bytes, transparently
// stripping a PEM "PKCS7" envelope when present.
func decode(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pkcs7: empty data")
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("pkcs7: invalid PEM")
		}
		return block.Bytes, nil
	}
	return data, nil
}
