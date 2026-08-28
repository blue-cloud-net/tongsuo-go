// Package sm2 基于铜锁原生实现实现 GB/T 32918 SM2 非对称算法。
//
// 提供密钥生成、PEM 序列化、加密/解密、签名/验签（SM2withSM3）。
// 签名与密文均为 ASN.1 DER 格式，与铜锁 openssl 输出一致。
package sm2

import (
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// DefaultID 为 SM2 默认用户标识（GM/T 0003-2012）。
var DefaultID = []byte("1234567812345678")

// PrivateKey 表示 SM2 私钥。
type PrivateKey struct {
	key *core.PKey
}

// PublicKey 表示 SM2 公钥。
type PublicKey struct {
	key *core.PKey
}

// GenerateKey 生成新的 SM2 密钥对。
func GenerateKey() (*PrivateKey, error) {
	k, err := core.GenerateSM2Key()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// Key 返回底层核心密钥对象（供内部跨包使用，如 x509）。
func (k *PrivateKey) Key() *core.PKey { return k.key }

// Key 返回底层核心密钥对象（供内部跨包使用，如 x509）。
func (k *PublicKey) Key() *core.PKey { return k.key }

// PublicKeyFromPKey 用底层核心密钥构造 PublicKey（供内部跨包使用，如 x509）。
func PublicKeyFromPKey(k *core.PKey) *PublicKey { return &PublicKey{key: k} }

// LoadPrivateKeyPEM 从 PEM（PKCS#8）加载 SM2 私钥。
func LoadPrivateKeyPEM(pem []byte) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载 SM2 公钥。
func LoadPublicKeyPEM(pem []byte) (*PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: k}, nil
}

// MarshalPEM 导出私钥为 PEM（PKCS#8）。
func (k *PrivateKey) MarshalPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// Public 返回对应的公钥（引用同一底层密钥）。
func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{key: k.key}
}

// MarshalPEM 导出公钥为 PEM（SubjectPublicKeyInfo）。
func (k *PublicKey) MarshalPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
}

// Encrypt 使用 SM2 公钥加密 data。
// 输出为 Tongsuo 8.x（OpenSSL 3.x）的 ASN.1 DER 格式（内含 C1C3C2），与
// `openssl pkeyutl -encrypt` 一致。
func Encrypt(pub *PublicKey, data []byte) ([]byte, error) {
	if pub == nil || pub.key == nil {
		return nil, fmt.Errorf("sm2: nil public key")
	}
	return pub.key.Encrypt(data)
}

// Decrypt 使用 SM2 私钥解密。
func Decrypt(priv *PrivateKey, data []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("sm2: nil private key")
	}
	return priv.key.Decrypt(data)
}

// Sign 使用 SM2withSM3 对 data 签名，返回 ASN.1 DER 签名。
func Sign(priv *PrivateKey, data []byte) ([]byte, error) {
	return SignWithID(priv, data, nil)
}

// Verify 使用 SM2withSM3 验签。
func Verify(pub *PublicKey, data, sig []byte) error {
	return VerifyWithID(pub, data, sig, nil)
}

// SignWithID 使用自定义 userId 对 data 签名。
func SignWithID(priv *PrivateKey, data, id []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("sm2: nil private key")
	}
	return priv.key.Sign(data, id)
}

// VerifyWithID 使用自定义 userId 验签。
func VerifyWithID(pub *PublicKey, data, sig, id []byte) error {
	if pub == nil || pub.key == nil {
		return fmt.Errorf("sm2: nil public key")
	}
	return pub.key.Verify(data, sig, id)
}

// ---------------------------------------------------------------------------
// SM2 密文格式转换（C1C2C3 ↔ C1C3C2 ↔ DER）
// ---------------------------------------------------------------------------
//
// SM2 密文由 C1（椭圆曲线点）、C3（SM3 哈希，32 字节）、C2（密文，与明文等长）组成。
// 常见表示有三种：
//   - "der"：ASN.1 DER（SEQUENCE { X INTEGER, Y INTEGER, Hash OCTET STRING, CT OCTET STRING }），
//     即 Tongsuo/OpenSSL 8.x `EVP_PKEY_encrypt` 的默认输出（内部顺序为 C1C3C2）；
//   - "c1c3c2"：裸格式，C1 || C3 || C2（国密标准推荐顺序）；
//   - "c1c2c3"：裸格式，C1 || C2 || C3。
//
// C1 为椭圆曲线点：未压缩点（0x04 前缀，65 字节）或压缩点（0x02/0x03 前缀，33 字节）。
// 裸格式互转对压缩/未压缩点均适用；与 DER 互转要求 C1 为未压缩点（DER 需要 X/Y 坐标）。

// sm2Cipher 为 SM2 密文的规范中间表示。
type sm2Cipher struct {
	c1   []byte // 原始 C1 点（65 未压缩 或 33 压缩）
	hash []byte // C3：32 字节
	c2   []byte // 密文
	x, y []byte // 未压缩点坐标（各 32 字节大端），仅未压缩点时有值
}

// Format 在 SM2 密文格式间转换。
// from/to 取值："der"、"c1c3c2"、"c1c2c3"。
// from 与 to 相同时返回 ct 的副本。
func Format(ct []byte, from, to string) ([]byte, error) {
	if from == to {
		return append([]byte{}, ct...), nil
	}
	var (
		c   *sm2Cipher
		err error
	)
	switch from {
	case "der":
		c, err = parseDER(ct)
	case "c1c3c2", "c1c2c3":
		c, err = parseRaw(ct, from == "c1c3c2")
	default:
		return nil, fmt.Errorf("sm2: unknown ciphertext format %q (want der/c1c3c2/c1c2c3)", from)
	}
	if err != nil {
		return nil, err
	}
	switch to {
	case "der":
		return buildDER(c)
	case "c1c3c2":
		return buildRaw(c, true), nil
	case "c1c2c3":
		return buildRaw(c, false), nil
	default:
		return nil, fmt.Errorf("sm2: unknown ciphertext format %q (want der/c1c3c2/c1c2c3)", to)
	}
}

// EncryptWithOrder 使用 SM2 公钥加密 data，输出指定顺序的裸格式密文。
// order 为 "c1c3c2"（默认）或 "c1c2c3"；返回的 C1 为未压缩点。
func EncryptWithOrder(pub *PublicKey, data []byte, order string) ([]byte, error) {
	if order == "" {
		order = "c1c3c2"
	}
	der, err := Encrypt(pub, data)
	if err != nil {
		return nil, err
	}
	return Format(der, "der", order)
}

// DecryptWithOrder 解密指定顺序的裸格式 SM2 密文。
// order 为 "c1c3c2"（默认）或 "c1c2c3"；C1 须为未压缩点。
func DecryptWithOrder(priv *PrivateKey, data []byte, order string) ([]byte, error) {
	if order == "" {
		order = "c1c3c2"
	}
	der, err := Format(data, order, "der")
	if err != nil {
		return nil, err
	}
	return Decrypt(priv, der)
}

// parseDER 解析 ASN.1 DER 密文。
func parseDER(ct []byte) (*sm2Cipher, error) {
	var s struct {
		X    *big.Int
		Y    *big.Int
		Hash []byte
		CT   []byte
	}
	if _, err := asn1.Unmarshal(ct, &s); err != nil {
		return nil, fmt.Errorf("sm2: invalid DER ciphertext: %w", err)
	}
	if s.X == nil || s.Y == nil {
		return nil, fmt.Errorf("sm2: invalid DER ciphertext: missing coordinates")
	}
	x := s.X.Bytes()
	y := s.Y.Bytes()
	if len(x) > 32 || len(y) > 32 {
		return nil, fmt.Errorf("sm2: invalid DER ciphertext: coordinate too large")
	}
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	copy(xb[32-len(x):], x)
	copy(yb[32-len(y):], y)
	c1 := make([]byte, 0, 65)
	c1 = append(c1, 0x04)
	c1 = append(c1, xb...)
	c1 = append(c1, yb...)
	return &sm2Cipher{c1: c1, hash: s.Hash, c2: s.CT, x: xb, y: yb}, nil
}

// buildDER 将规范中间表示组装为 ASN.1 DER 密文。
func buildDER(c *sm2Cipher) ([]byte, error) {
	if c.x == nil || c.y == nil {
		return nil, fmt.Errorf("sm2: cannot convert compressed C1 to DER")
	}
	d, err := asn1.Marshal(struct {
		X    *big.Int
		Y    *big.Int
		Hash []byte
		CT   []byte
	}{
		X:    new(big.Int).SetBytes(c.x),
		Y:    new(big.Int).SetBytes(c.y),
		Hash: c.hash,
		CT:   c.c2,
	})
	if err != nil {
		return nil, fmt.Errorf("sm2: marshal DER ciphertext: %w", err)
	}
	return d, nil
}

// c1Len 返回 C1 点长度（未压缩 65 / 压缩 33）。
func c1Len(ct []byte) (int, error) {
	if len(ct) == 0 {
		return 0, fmt.Errorf("sm2: empty ciphertext")
	}
	switch ct[0] {
	case 0x04:
		return 65, nil
	case 0x02, 0x03:
		return 33, nil
	default:
		return 0, fmt.Errorf("sm2: unsupported C1 point prefix 0x%02x", ct[0])
	}
}

// parseRaw 解析裸格式密文。hashFirst=true 表示 C1C3C2，否则 C1C2C3。
func parseRaw(ct []byte, hashFirst bool) (*sm2Cipher, error) {
	n, err := c1Len(ct)
	if err != nil {
		return nil, err
	}
	if len(ct) < n+32 {
		return nil, fmt.Errorf("sm2: ciphertext too short for C1+C3")
	}
	c := &sm2Cipher{c1: append([]byte{}, ct[:n]...)}
	if hashFirst {
		c.hash = append([]byte{}, ct[n:n+32]...)
		c.c2 = append([]byte{}, ct[n+32:]...)
	} else {
		c.c2 = append([]byte{}, ct[n:len(ct)-32]...)
		c.hash = append([]byte{}, ct[len(ct)-32:]...)
	}
	if ct[0] == 0x04 {
		c.x = append([]byte{}, ct[1:33]...)
		c.y = append([]byte{}, ct[33:65]...)
	}
	return c, nil
}

// buildRaw 组装裸格式密文。hashFirst=true 输出 C1C3C2，否则 C1C2C3。
func buildRaw(c *sm2Cipher, hashFirst bool) []byte {
	out := make([]byte, 0, len(c.c1)+len(c.hash)+len(c.c2))
	out = append(out, c.c1...)
	if hashFirst {
		out = append(out, c.hash...)
		out = append(out, c.c2...)
	} else {
		out = append(out, c.c2...)
		out = append(out, c.hash...)
	}
	return out
}
