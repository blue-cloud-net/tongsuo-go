package core

import (
	"encoding/asn1"
	"fmt"
	"math/big"
	"runtime"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

const maxSerialOctets = 20

// ValidateSerial 检查正数序列号及含符号补零的 20 octets 边界。
//
// ValidateSerial checks a positive serial and the 20-octet DER content limit including sign padding.
func ValidateSerial(serial *big.Int) error {
	if serial == nil || serial.Sign() <= 0 {
		return fmt.Errorf("x509: serial must be positive")
	}
	if serial.BitLen() > maxSerialOctets*8-1 {
		return fmt.Errorf("x509: serial exceeds 20 DER octets")
	}
	return nil
}

// SerialBigInt 返回独立的完整带符号序列号；无效句柄或转换失败返回错误。
//
// SerialBigInt returns an independent complete signed serial; invalid handles or conversions fail.
func (c *Certificate) SerialBigInt() (*big.Int, error) {
	defer runtime.KeepAlive(c)
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil, fmt.Errorf("x509: certificate closed")
	}
	n, ok := new(big.Int).SetString(native.X509_get_serial_hex(c.handle.Ptr()), 16)
	if !ok {
		return nil, fmt.Errorf("x509: invalid serial number")
	}
	return n, nil
}

// SetSerialBigInt 复制并写入完整正数序列号，拒绝签名后修改及超过 20 octets 的值。
//
// SetSerialBigInt copies and writes a positive serial, rejecting signed certificates and values over 20 octets.
func (c *Certificate) SetSerialBigInt(serial *big.Int) error {
	defer runtime.KeepAlive(c)
	if err := c.ensureMutable("set serial"); err != nil {
		return err
	}
	if err := ValidateSerial(serial); err != nil {
		return err
	}
	if !native.X_X509_set_serial_hex(c.handle.Ptr(), serial.Text(16)) {
		return NewOpError("x509: set serial", native.PopError())
	}
	return nil
}

// AddExtensionOIDDER 添加原始 DER 扩展，不允许签名后修改；参数或原生失败返回错误。
//
// AddExtensionOIDDER adds raw DER before signing; invalid parameters and native failures return errors.
func (c *Certificate) AddExtensionOIDDER(oid string, critical bool, der []byte) error {
	defer runtime.KeepAlive(c)
	if err := c.ensureMutable("add extension DER"); err != nil {
		return err
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil || len(rest) != 0 || len(der) == 0 || int64(len(der)) > 2147483647 || strings.ContainsRune(oid, 0) {
		return fmt.Errorf("x509: invalid extension OID or DER")
	}
	if !native.X_X509_add_ext_der(c.handle.Ptr(), oid, critical, der) {
		return NewOpError("x509: add extension DER", native.PopError())
	}
	return nil
}

// SetDefaultPaths 加载铜锁默认信任路径；已关闭存储或原生失败返回错误。
//
// SetDefaultPaths loads Tongsuo trust paths; closed stores and native failures return errors.
func (s *Store) SetDefaultPaths() error {
	defer runtime.KeepAlive(s)
	if s == nil || s.handle == nil || s.handle.IsClosed() {
		return fmt.Errorf("x509: store closed")
	}
	if !native.X509_STORE_set_default_paths(s.handle.Ptr()) {
		return NewOpError("x509: default paths", native.PopError())
	}
	return nil
}

// LoadLocations 加载指定 CA 文件/目录，不隐式信任输入链。
//
// LoadLocations loads a CA file/directory without implicitly trusting input chains.
func (s *Store) LoadLocations(file, dir string) error {
	defer runtime.KeepAlive(s)
	if s == nil || s.handle == nil || s.handle.IsClosed() {
		return fmt.Errorf("x509: store closed")
	}
	if file == "" && dir == "" || strings.ContainsRune(file, 0) || strings.ContainsRune(dir, 0) {
		return fmt.Errorf("x509: invalid CA locations")
	}
	if !native.X509_STORE_load_locations(s.handle.Ptr(), file, dir) {
		return NewOpError("x509: load locations", native.PopError())
	}
	return nil
}

// ExpandSM2Point 返回经铜锁校验展开的 SM2 公共点；无效点返回错误。
//
// ExpandSM2Point expands a validated SM2 public point through Tongsuo or returns an error.
func ExpandSM2Point(point []byte) ([]byte, error) {
	out, ok := native.X_SM2_expand_point(point)
	if !ok {
		return nil, NewOpError("sm2: invalid compressed C1", native.PopError())
	}
	return out, nil
}

// ReencryptPassword 无损改密，替换成功后才释放旧句柄；空 pbe 保留原算法策略。
//
// ReencryptPassword changes passwords losslessly, replacing the handle only on success; empty pbe preserves algorithms.
func (p *PKCS12) ReencryptPassword(oldPass, newPass, pbe string, iter int, name string) error {
	defer runtime.KeepAlive(p)
	if p == nil || p.handle == nil || p.handle.IsClosed() {
		return fmt.Errorf("pkcs12: closed")
	}
	if strings.ContainsRune(oldPass, 0) || strings.ContainsRune(newPass, 0) || strings.ContainsRune(name, 0) {
		return fmt.Errorf("pkcs12: NUL in password or name")
	}
	next := native.X_PKCS12_reencrypt(p.handle.Ptr(), oldPass, newPass, pbe, iter, name)
	if next == nil {
		return NewOpError("pkcs12: lossless reencrypt (unsupported structure, algorithm, ambiguous name, or invalid password/MAC)", native.PopError())
	}
	if err := p.handle.Close(); err != nil {
		native.PKCS12_free(next)
		return err
	}
	p.handle = NewHandle(next, true, native.PKCS12_free)
	return nil
}
