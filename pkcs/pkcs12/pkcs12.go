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

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/certaccess"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/keyaccess"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// coreCertOf 经 internal/certaccess 取出证书的底层 *core.Certificate 句柄。
//
// x509 已弃用 Certificate.Core()（roadmap §5 E1-8：公开签名中不得出现 internal/
// 类型），跳包取证书句柄统一走桥接包；取不到时返回错误。
//
// coreCertOf extracts the underlying *core.Certificate handle through
// internal/certaccess.
//
// x509 deprecated Certificate.Core() (roadmap §5, E1-8: no public signature may
// mention an internal/ type), so cross-package handle access goes through the
// bridge package. A failure returns an error.
func coreCertOf(c *x509.Certificate) (*core.Certificate, error) {
	h, ok := certaccess.Certificate(c)
	if !ok || h == nil {
		return nil, fmt.Errorf("pkcs12: certificate handle unavailable")
	}
	return h, nil
}

// PrivateKey 表示可打包进 PKCS#12 的私钥。
//
// 本类型是 asym.PrivateKey 的别名（roadmap §5 E1-12：原为 key.CoreKey 别名）。
// 跨包取底层句柄经 internal/keyaccess。
//
// PrivateKey is the private key that can be packed into a PKCS#12 container.
//
// It aliases asym.PrivateKey (roadmap §5, E1-12: previously an alias of
// key.CoreKey). The underlying handle is obtained through internal/keyaccess.
type PrivateKey = asym.PrivateKey

// Bundle 表示解析后的 PKCS#12 内容。
//
// PrivateKey 为 asym.PrivateKey（拥有自己的底层句柄，调用方需用 asym.Close 释放）。
//
// Bundle is the parsed content of a PKCS#12 container. PrivateKey is an
// asym.PrivateKey owning its underlying handle; release it with asym.Close.
type Bundle struct {
	PrivateKey  asym.PrivateKey     // 私钥（调用方负责 asym.Close）
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
	keyCore, ok := keyaccess.PKey(key)
	if !ok || keyCore == nil {
		return nil, fmt.Errorf("pkcs12: unsupported private key type %T", key)
	}
	ccerts := make([]*core.Certificate, 0, len(ca))
	for _, c := range ca {
		if c != nil {
			h, err := coreCertOf(c)
			if err != nil {
				return nil, err
			}
			ccerts = append(ccerts, h)
		}
	}
	certCore, err := coreCertOf(cert)
	if err != nil {
		return nil, err
	}
	p12, err := core.CreatePKCS12(password, name, keyCore, certCore, ccerts)
	if err != nil {
		return nil, err
	}
	defer p12.Close()
	return p12.MarshalDER()
}

// Parse 从 DER 解析 PKCS#12。
// 解析后的 Bundle 中 PrivateKey 为 asym.PrivateKey（调用方用 asym.Close 释放）；
// 容器不含主证书时 Certificate 为 nil。
//
// 实现上先把内部句柄经 internal/keyaccess 的 PEM 往返换成 asym 对象
// （roadmap §5 E1-12：字段由原生句柄改为 asym.PrivateKey）。
//
// Parse parses a PKCS#12 container from DER. On success it returns a Bundle
// whose PrivateKey field is an asym.PrivateKey (release it with asym.Close);
// when the container has no leaf certificate, Certificate is nil.
//
// Internally the raw handle goes through internal/keyaccess's PEM round trip to
// become an asym value (roadmap §5, E1-12: the field changed from the native
// handle to asym.PrivateKey).
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
	b := &Bundle{}
	if key != nil {
		wrapped, werr := keyaccess.WrapPrivateKey(key)
		if werr != nil {
			return nil, werr
		}
		b.PrivateKey = wrapped
	}
	if cert != nil {
		wrapped, werr := certaccess.Wrap(cert)
		if werr != nil {
			return nil, werr
		}
		b.Certificate = wrapped
	}
	for _, c := range ca {
		wrapped, werr := certaccess.Wrap(c)
		if werr != nil {
			return nil, werr
		}
		b.CACerts = append(b.CACerts, wrapped)
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
