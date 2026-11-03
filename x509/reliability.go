package x509

import (
	"fmt"
	"math/big"
	"time"
)

// SerialBigInt 无损读取完整带符号序列号，返回独立对象；无效证书返回错误。
//
// SerialBigInt reads the full signed serial as an independent integer or fails for invalid certificates.
func (c *Certificate) SerialBigInt() (*big.Int, error) {
	if c == nil || c.cert == nil {
		return nil, fmt.Errorf("x509: certificate closed")
	}
	return c.cert.SerialBigInt()
}

// SetSerialBigInt 复制正数序列号，校验含符号补零的 20 octets 边界；签名后拒绝修改。
//
// SetSerialBigInt copies a positive serial within 20 DER octets including sign padding, before signing only.
func (c *Certificate) SetSerialBigInt(serial *big.Int) error {
	if c == nil || c.cert == nil {
		return fmt.Errorf("x509: certificate closed")
	}
	return c.cert.SetSerialBigInt(serial)
}

// SerialBigInt 从完整 SerialHex 返回独立大整数；缺失或无效时返回错误。
//
// SerialBigInt returns an independent integer from SerialHex, failing if absent or invalid.
func (e RevokedEntry) SerialBigInt() (*big.Int, error) {
	n, ok := new(big.Int).SetString(e.SerialHex, 16)
	if !ok {
		return nil, fmt.Errorf("x509: invalid revoked serial")
	}
	return n, nil
}

// RevokeSerial 复制正数序列号添加吊销条目；调用方负责序列号归属与授权。
// 参数、已关闭或已签名构建器返回错误。
//
// RevokeSerial copies a positive serial into a revocation entry; callers establish issuer ownership and authority.
// Invalid parameters and closed or signed builders return errors.
func (b *CRLBuilder) RevokeSerial(serial *big.Int, at time.Time, reason RevocationReason) error {
	if b == nil || b.crl == nil {
		return errBuilderClosed()
	}
	if !validRevocationReason(reason) {
		return fmt.Errorf("x509: invalid revocation reason %d", reason)
	}
	return b.crl.AddRevokedSerial(serial, at, int(reason))
}

// RevokeSerialHex 按无前缀十六进制正数吊销，允许大小写及前导零；其余校验同 RevokeSerial。
//
// RevokeSerialHex accepts bare hexadecimal positive serials, including mixed case and leading zeros; RevokeSerial validates the rest.
func (b *CRLBuilder) RevokeSerialHex(serial string, at time.Time, reason RevocationReason) error {
	if serial == "" {
		return fmt.Errorf("x509: empty serial")
	}
	for _, c := range serial {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return fmt.Errorf("x509: invalid hex serial")
		}
	}
	n, ok := new(big.Int).SetString(serial, 16)
	if !ok {
		return fmt.Errorf("x509: invalid hex serial")
	}
	return b.RevokeSerial(n, at, reason)
}

// AddExtensionDER 按已知或自定义 OID 写入单个原始 DER 值，仍禁止签名后修改。
//
// AddExtensionDER adds a raw DER value by known or custom OID, rejecting changes after signing.
func (c *Certificate) AddExtensionDER(oid string, critical bool, der []byte) error {
	if c == nil || c.cert == nil {
		return fmt.Errorf("x509: certificate closed")
	}
	return c.cert.AddExtensionOIDDER(oid, critical, der)
}

// SetDefaultPaths 加载铜锁配置的默认信任路径，不承诺平台原生信任库。
//
// SetDefaultPaths loads Tongsuo-configured trust paths, which need not be the platform native trust store.
func (s *Store) SetDefaultPaths() error {
	if s == nil || s.store == nil {
		return fmt.Errorf("x509: store closed")
	}
	return s.store.SetDefaultPaths()
}

// LoadLocations 加载 CA 文件或散列 CA 目录，空路径不使用；两者均空或存储关闭报错。
//
// LoadLocations loads a CA file or hashed CA directory; empty paths are unused and both-empty or closed stores fail.
func (s *Store) LoadLocations(caFile, caDir string) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("x509: store closed")
	}
	return s.store.LoadLocations(caFile, caDir)
}
