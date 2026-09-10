// Package sm2 基于铜锁原生实现实现 GB/T 32918 SM2 非对称算法。
// 提供密钥生成、PEM 序列化、加密/解密、签名/验签（SM2withSM3）。
// 签名与密文均为 ASN.1 DER 格式，与铜锁 openssl 输出一致。
//
// Package sm2 provides the GB/T 32918 SM2 asymmetric algorithm backed by the
// Tongsuo native library. It exposes key generation, PEM serialization,
// public key encryption/decryption, and SM2withSM3 signing/verification.
// Signatures and ciphertexts are emitted in ASN.1 DER, matching the output
// of Tongsuo's openssl CLI.
package sm2

import (
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// DefaultID 为 SM2 默认用户标识（GM/T 0003-2012）。
//
// DefaultID is the default SM2 user identifier per GM/T 0003-2012.
var DefaultID = []byte("1234567812345678")

// SM2 密文格式常量（GB/T 32918.4-2016）。
//
// Coordinates are 32 bytes each on the sm2p256v1 curve; an uncompressed
// C1 point is therefore 1 prefix byte + 2*32 = 65 bytes, a compressed
// one is 1 + 32 = 33 bytes.
const (
	coordBytes         = 32   // 单坐标字节长度
	c1UncompressedLen  = 65   // 未压缩 C1 点（0x04 前缀 + X + Y）
	c1CompressedLen    = 33   // 压缩 C1 点（0x02/0x03 前缀 + X）
	c1PrefixUncomp     = 0x04 // 未压缩点前缀
	c1PrefixCompEven   = 0x02 // 压缩点偶数 Y 前缀
	c1PrefixCompOdd    = 0x03 // 压缩点奇数 Y 前缀
)

// PrivateKey 表示 SM2 私钥。
//
// PrivateKey represents an SM2 private key.
type PrivateKey struct {
	key *core.PKey
}

// PublicKey 表示 SM2 公钥。
//
// PublicKey represents an SM2 public key.
type PublicKey struct {
	key *core.PKey
}

// GenerateKey 生成新的 SM2 密钥对。
//
// GenerateKey generates a fresh SM2 key pair.
func GenerateKey() (*PrivateKey, error) {
	k, err := core.GenerateSM2Key()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// Key 返回底层核心密钥对象（供内部跨包使用，如 x509）。
// 不是稳定的公共 API 的一部分；仅供内部跨包使用，外部代码不应依赖其返回类型。
//
// Key returns the underlying core.PKey handle. It is intended for cross-package
// internal use (for example, by the x509 package) and is not part of the
// stable public API.
func (k *PrivateKey) Key() *core.PKey { return k.key }

// Key 返回底层核心密钥对象（供内部跨包使用，如 x509）。
// 不是稳定的公共 API 的一部分；仅供内部跨包使用，外部代码不应依赖其返回类型。
//
// Key returns the underlying core.PKey handle. It is intended for cross-package
// internal use (for example, by the x509 package) and is not part of the
// stable public API.
func (k *PublicKey) Key() *core.PKey { return k.key }

// PublicKeyFromPKey 用底层核心密钥构造 PublicKey（供内部跨包使用，如 x509）。
// 不是稳定的公共 API 的一部分；仅供内部跨包使用，外部代码不应调用。
//
// PublicKeyFromPKey wraps a low-level core.PKey handle into a PublicKey.
// It is intended for cross-package internal use (for example, by x509) and is
// not part of the stable public API.
func PublicKeyFromPKey(k *core.PKey) *PublicKey { return &PublicKey{key: k} }

// LoadPrivateKeyPEM 从 PEM（PKCS#8）加载 SM2 私钥。
// PEM 块头形如 "-----BEGIN PRIVATE KEY-----"。
//
// LoadPrivateKeyPEM loads an SM2 private key from a PKCS#8 PEM block
// ("-----BEGIN PRIVATE KEY-----").
func LoadPrivateKeyPEM(pem []byte) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载 SM2 公钥。
// PEM 块头形如 "-----BEGIN PUBLIC KEY-----"。
//
// LoadPublicKeyPEM loads an SM2 public key from a SubjectPublicKeyInfo PEM
// block ("-----BEGIN PUBLIC KEY-----").
func LoadPublicKeyPEM(pem []byte) (*PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: k}, nil
}

// MarshalPEM 导出私钥为 PEM（PKCS#8）。
//
// MarshalPEM serializes the private key as a PKCS#8 PEM block.
func (k *PrivateKey) MarshalPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// Public 返回对应的公钥（引用同一底层密钥）；两个值共享同一个底层 core.PKey 句柄。
//
// Public returns the public key corresponding to the private key. Both
// values share the same underlying core.PKey handle.
func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{key: k.key}
}

// MarshalPEM 导出公钥为 PEM（SubjectPublicKeyInfo）。
//
// MarshalPEM serializes the public key as a SubjectPublicKeyInfo PEM block.
func (k *PublicKey) MarshalPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
}

// Encrypt 使用 SM2 公钥加密 data，输出为 Tongsuo 8.x（OpenSSL 3.x）的 ASN.1 DER 格式
// （内含 C1C3C2），与 `openssl pkeyutl -encrypt` 一致。
//
// Encrypt encrypts data with the given SM2 public key and returns the
// ciphertext in ASN.1 DER (C1C3C2 internal order), matching the format
// emitted by `openssl pkeyutl -encrypt` under Tongsuo 8.x (OpenSSL 3.x).
func Encrypt(pub *PublicKey, data []byte) ([]byte, error) {
	if pub == nil || pub.key == nil {
		return nil, fmt.Errorf("sm2: nil public key")
	}
	// SM2 算法不支持空明文（GB/T 32918.4 无空消息约定）。此检查放在公开层
	//（而非 core 的通用 Encrypt），以免误伤允许空明文的 RSA 路径。
	if len(data) == 0 {
		return nil, fmt.Errorf("sm2: empty plaintext not supported")
	}
	return pub.key.Encrypt(data)
}

// Decrypt 使用 SM2 私钥解密 ASN.1 DER 格式的 SM2 密文。
//
// Decrypt decrypts an SM2 ciphertext (ASN.1 DER) with the corresponding
// private key.
func Decrypt(priv *PrivateKey, data []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("sm2: nil private key")
	}
	return priv.key.Decrypt(data)
}

// Sign 使用 SM2withSM3 对 data 签名，返回 ASN.1 DER 签名。
// 使用默认用户标识符 DefaultID（GM/T 0003-2012 规定值）；验签时也须使用同一 ID。
//
// Sign signs data with SM2withSM3 and returns the signature in ASN.1 DER.
// It uses the default user identifier DefaultID.
func Sign(priv *PrivateKey, data []byte) ([]byte, error) {
	return SignWithID(priv, data, nil)
}

// Verify 使用 SM2withSM3 验签。
// 使用默认用户标识符 DefaultID；与签名 Sign 时使用的 ID 必须一致。
//
// Verify reports whether sig is a valid SM2withSM3 signature of data under pub.
// It uses the default user identifier DefaultID.
func Verify(pub *PublicKey, data, sig []byte) error {
	return VerifyWithID(pub, data, sig, nil)
}

// SignWithID 使用自定义 userId 对 data 签名。
// 使用 SM2withSM3 算法。
// id 传 nil 时回退到默认用户标识符 DefaultID（GM/T 0003-2012）。
//
// SignWithID signs data with SM2withSM3 using a custom user identifier id.
// Pass nil to use DefaultID.
func SignWithID(priv *PrivateKey, data, id []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("sm2: nil private key")
	}
	return priv.key.Sign(data, id)
}

// VerifyWithID 使用自定义 userId 验签。
// 使用 SM2withSM3 算法。
// id 传 nil 时回退到默认用户标识符 DefaultID；与签名时使用的 ID 必须一致。
//
// VerifyWithID reports whether sig is a valid SM2withSM3 signature of data
// under pub, using a custom user identifier id. Pass nil to use DefaultID.
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
//
// sm2Cipher is the canonical intermediate representation of an SM2
// ciphertext used by Format / EncryptWithOrder / DecryptWithOrder.
type sm2Cipher struct {
	c1   []byte // 原始 C1 点（65 未压缩 或 33 压缩）
	hash []byte // C3：32 字节
	c2   []byte // 密文
	x, y []byte // 未压缩点坐标（各 32 字节大端），仅未压缩点时有值
}

// Format 在 SM2 密文格式间转换。
// from/to 取值："der"、"c1c3c2"、"c1c2c3"。
// from 与 to 相同时返回 ct 的副本。
//
// Format converts an SM2 ciphertext between representations. from and to must
// be one of "der", "c1c3c2", or "c1c2c3". When from == to a copy of ct is
// returned. Conversions involving "der" require an uncompressed C1 point.
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
//
// EncryptWithOrder encrypts data with the SM2 public key and returns the
// raw-format ciphertext in the requested order. order must be "c1c3c2"
// (the default when empty) or "c1c2c3"; the returned C1 point is always
// uncompressed.
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
//
// DecryptWithOrder decrypts a raw-format SM2 ciphertext in the given order.
// order must be "c1c3c2" (the default when empty) or "c1c2c3"; C1 must be
// an uncompressed point.
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
//
// parseDER parses an SM2 ciphertext encoded as ASN.1 DER (the SEQUENCE
// { X, Y, Hash, CT } format produced by Tongsuo/OpenSSL EVP_PKEY_encrypt).
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
	if len(x) > coordBytes || len(y) > coordBytes {
		return nil, fmt.Errorf("sm2: invalid DER ciphertext: coordinate too large")
	}
	xb := make([]byte, coordBytes)
	yb := make([]byte, coordBytes)
	copy(xb[coordBytes-len(x):], x)
	copy(yb[coordBytes-len(y):], y)
	c1 := make([]byte, 0, c1UncompressedLen)
	c1 = append(c1, c1PrefixUncomp)
	c1 = append(c1, xb...)
	c1 = append(c1, yb...)
	return &sm2Cipher{c1: c1, hash: s.Hash, c2: s.CT, x: xb, y: yb}, nil
}

// buildDER 将规范中间表示组装为 ASN.1 DER 密文。
//
// buildDER marshals an *sm2Cipher back into the ASN.1 DER SEQUENCE
// format (with an uncompressed C1 point in the X/Y coordinates).
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
//
// c1Len inspects the C1 prefix byte and returns the length of the
// elliptic-curve point: 65 bytes for an uncompressed (0x04) point and
// 33 bytes for a compressed (0x02 / 0x03) point.
func c1Len(ct []byte) (int, error) {
	if len(ct) == 0 {
		return 0, fmt.Errorf("sm2: empty ciphertext")
	}
	switch ct[0] {
	case c1PrefixUncomp:
		return c1UncompressedLen, nil
	case c1PrefixCompEven, c1PrefixCompOdd:
		return c1CompressedLen, nil
	default:
		return 0, fmt.Errorf("sm2: unsupported C1 point prefix 0x%02x", ct[0])
	}
}

// parseRaw 解析裸格式密文。hashFirst=true 表示 C1C3C2，否则 C1C2C3。
//
// parseRaw splits a raw-format SM2 ciphertext into its C1 point, C3
// hash and C2 body. hashFirst selects the layout: C1||C3||C2 when true,
// C1||C2||C3 otherwise.
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
//
// buildRaw emits an *sm2Cipher as a raw-format SM2 ciphertext. hashFirst
// selects the layout: C1||C3||C2 when true, C1||C2||C3 otherwise.
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
