// Package pkcs12 基于铜锁原生实现实现 PKCS#12 容器（.p12 / .pfx）。
// 提供打包（证书 + 私钥 + CA 链 + 口令）、解析与改密。输入输出均为 DER 编码，
// 与 `openssl pkcs12` 互通。
//
// Package pkcs12 implements the PKCS#12 container (.p12 / .pfx) backed by the
// Tongsuo native library. It provides Pack (certificate + private key + CA
// chain + password), Parse and ChangePassword; inputs and outputs are DER
// and interoperable with `openssl pkcs12`.
package pkcs12

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/key"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// PrivateKey 表示可打包进 PKCS#12 的私钥（sm2 / rsa / ecdsa 私钥与
// key.PrivateKey 均实现）。
//
// 本类型是 key.CoreKey 的别名：任一持底层 core.PKey 的私钥类型（含统合密钥
// key.PrivateKey）都可直接传给 Pack，无需先取出底层句柄。
//
// PrivateKey is the private key that can be packed into a PKCS#12 container;
// the private key types of sm2 / rsa / ecdsa and key.PrivateKey all satisfy it.
//
// It is an alias of key.CoreKey: any private-key type exposing an underlying
// core.PKey (including the unified key.PrivateKey) can be passed to Pack
// directly, without extracting the underlying handle first.
type PrivateKey = key.CoreKey

// Bundle 表示解析后的 PKCS#12 内容。
//
// PrivateKey 为最通用的底层 core.PKey 句柄（可直接 Close / Equal / 签名，或经
// key.LoadPrivateKeyPEM 重新包装为统合密钥类型）。
//
// Bundle is the parsed content of a PKCS#12 container; PrivateKey must be
// Closed by the caller. It is the raw core.PKey handle — the most general
// form — usable directly for Close / Equal / signing, or re-wrapped into a
// unified key type via key.LoadPrivateKeyPEM.
type Bundle struct {
	PrivateKey  *core.PKey          // 私钥（调用方负责 Close）
	Certificate *x509.Certificate   // 主证书
	CACerts     []*x509.Certificate // CA 链
}

// Pack 将证书、私钥与 CA 链打包为 PKCS#12（DER）。
// password 为口令；name 为友好名称（可空）。
// cert 与 key 必须非 nil；ca 中的 nil 条目会被静默跳过。
//
// Pack packages a certificate, private key and CA chain into a PKCS#12
// container (DER). cert and key must be non-nil; nil entries in ca are
// silently skipped. password is the encryption password; name is the
// friendly name (may be empty).
func Pack(cert *x509.Certificate, key PrivateKey, ca []*x509.Certificate, password, name string) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("pkcs12: nil certificate")
	}
	if key == nil {
		return nil, fmt.Errorf("pkcs12: nil private key")
	}
	ccerts := make([]*core.Certificate, 0, len(ca))
	for _, c := range ca {
		if c != nil {
			ccerts = append(ccerts, c.Core())
		}
	}
	p12, err := core.CreatePKCS12(password, name, key.Key(), cert.Core(), ccerts)
	if err != nil {
		return nil, err
	}
	defer p12.Close()
	return p12.MarshalDER()
}

// Parse 从 DER 解析 PKCS#12。
// 解析后的 Bundle 中 PrivateKey 包装底层 core.PKey（调用方负责 Close）；
// 容器不含主证书时 Certificate 为 nil。
//
// Parse parses a PKCS#12 container from DER. On success it returns a Bundle
// whose PrivateKey field wraps the underlying core.PKey (must be Closed by
// the caller); when the container has no leaf certificate, Certificate is nil.
func Parse(data []byte, password string) (*Bundle, error) {
	p12, err := core.LoadPKCS12DER(data)
	if err != nil {
		return nil, err
	}
	defer p12.Close()
	key, cert, ca, err := p12.Parse(password)
	if err != nil {
		return nil, err
	}
	b := &Bundle{PrivateKey: key}
	if cert != nil {
		b.Certificate = x509.WrapCertificate(cert)
	}
	for _, c := range ca {
		b.CACerts = append(b.CACerts, x509.WrapCertificate(c))
	}
	return b, nil
}

// ChangePassword 修改 PKCS#12 口令（输入输出均为 DER）。
//
// ChangePassword rewrites the encryption password of a PKCS#12 container;
// both input and output are DER.
func ChangePassword(data []byte, oldPass, newPass string) ([]byte, error) {
	p12, err := core.LoadPKCS12DER(data)
	if err != nil {
		return nil, err
	}
	defer p12.Close()
	if err := p12.ChangePassword(oldPass, newPass); err != nil {
		return nil, err
	}
	return p12.MarshalDER()
}
