package asym

import (
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// sm2PrivateKey 是 SM2 私钥的具体类型（非导出）。
// 公钥通过 Public() 取得；外部包无法直接构造该类型。
//
// sm2PrivateKey is the concrete (unexported) type for SM2 private keys.
// The corresponding public key is reachable via Public(); external
// packages cannot construct this type directly.
type sm2PrivateKey struct {
	key *core.PKey
}

// sm2PublicKey 是 SM2 公钥的具体类型（非导出）。
//
// sm2PublicKey is the concrete (unexported) type for SM2 public keys.
type sm2PublicKey struct {
	key *core.PKey
}

// Algorithm 实现 Key 接口。
func (k *sm2PrivateKey) Algorithm() Algorithm { return AlgSM2 }

// Algorithm 实现 Key 接口。
func (k *sm2PublicKey) Algorithm() Algorithm { return AlgSM2 }

// corePKey 实现 Key 接口（同包内可见）。
func (k *sm2PrivateKey) corePKey() *core.PKey { return k.key }

// corePKey 实现 Key 接口。
func (k *sm2PublicKey) corePKey() *core.PKey { return k.key }

// Public 返回与本私钥配对的 SM2 公钥（共享同一底层 core.PKey）。
//
// Public returns the SM2 public key paired with this private key,
// sharing the same underlying core.PKey handle.
func (k *sm2PrivateKey) Public() PublicKey {
	return &sm2PublicKey{key: k.key}
}

// MarshalPrivateKeyPEM 将 SM2 私钥导出为 PKCS#8 PEM。
//
// MarshalPrivateKeyPEM serializes the private key as a PKCS#8 PEM block.
func (k *sm2PrivateKey) MarshalPrivateKeyPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalPublicKeyPEM 将 SM2 公钥导出为 SubjectPublicKeyInfo PEM。
//
// MarshalPublicKeyPEM serializes the public key as a SPKI PEM block.
func (k *sm2PublicKey) MarshalPublicKeyPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
}

// GenerateSM2 生成新的 SM2 密钥对。
//
// GenerateSM2 generates a fresh SM2 key pair.
func GenerateSM2() (PrivateKey, error) {
	k, err := core.GenerateSM2Key()
	if err != nil {
		return nil, err
	}
	return &sm2PrivateKey{key: k}, nil
}

// LoadPrivateKeyPEM 从 PKCS#8 PEM 加载 SM2 私钥。
// 块头形如 "-----BEGIN PRIVATE KEY-----"。
//
// LoadPrivateKeyPEM loads an SM2 private key from a PKCS#8 PEM block
// ("-----BEGIN PRIVATE KEY-----").
func LoadPrivateKeyPEM(pem []byte) (PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &sm2PrivateKey{key: k}, nil
}

// LoadPublicKeyPEM 从 SubjectPublicKeyInfo PEM 加载 SM2 公钥。
//
// LoadPublicKeyPEM loads an SM2 public key from a SPKI PEM block
// ("-----BEGIN PUBLIC KEY-----").
func LoadPublicKeyPEM(pem []byte) (PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &sm2PublicKey{key: k}, nil
}

// Sign 使用 SM2withSM3 对 data 签名，返回 ASN.1 DER 签名。
// id 传 nil 时回退到 DefaultSM2ID。
//
// Sign signs data with SM2withSM3 and returns the signature in ASN.1 DER.
// Pass id=nil to use DefaultSM2ID.
func Sign(priv PrivateKey, data []byte) ([]byte, error) {
	return SignWithID(priv, data, nil)
}

// Verify 验签 SM2withSM3 签名。
// id 传 nil 时回退到 DefaultSM2ID；与签名时使用的 ID 必须一致。
//
// Verify reports whether sig is a valid SM2withSM3 signature of data
// under pub. Pass id=nil to use DefaultSM2ID; the id used here must
// match the one used during signing.
func Verify(pub PublicKey, data, sig []byte) error {
	return VerifyWithID(pub, data, sig, nil)
}

// SignWithID 使用自定义 userId 对 data 签名。
//
// SignWithID signs data with SM2withSM3 using a custom user identifier.
// Pass id=nil to fall back to DefaultSM2ID.
func SignWithID(priv PrivateKey, data, id []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: nil private key")
	}
	if k, ok := priv.(*sm2PrivateKey); ok {
		return k.key.Sign(data, id)
	}
	return nil, fmt.Errorf("asym: Sign requires an SM2 key, got %s", priv.Algorithm())
}

// VerifyWithID 使用自定义 userId 验签。
//
// VerifyWithID reports whether sig is a valid SM2withSM3 signature of data
// under pub, using a custom user identifier id.
func VerifyWithID(pub PublicKey, data, sig, id []byte) error {
	if pub == nil {
		return fmt.Errorf("asym: nil public key")
	}
	if k, ok := pub.(*sm2PublicKey); ok {
		return k.key.Verify(data, sig, id)
	}
	return fmt.Errorf("asym: Verify requires an SM2 key, got %s", pub.Algorithm())
}

// Encrypt 使用 SM2 公钥加密 data。
// 输出为 ASN.1 DER 格式（C1C3C2），与 Tongsuo/OpenSSL 的 EVP_PKEY_encrypt 一致。
//
// Encrypt encrypts data with the given SM2 public key and returns the
// ciphertext in ASN.1 DER (C1C3C2 internal order), matching the format
// emitted by Tongsuo's EVP_PKEY_encrypt.
func Encrypt(pub PublicKey, data []byte) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("asym: nil public key")
	}
	if k, ok := pub.(*sm2PublicKey); ok {
		if len(data) == 0 {
			return nil, fmt.Errorf("asym: sm2: empty plaintext not supported")
		}
		return k.key.Encrypt(data)
	}
	return nil, fmt.Errorf("asym: Encrypt requires an SM2 key, got %s", pub.Algorithm())
}

// Decrypt 使用 SM2 私钥解密 ASN.1 DER 密文。
//
// Decrypt decrypts an SM2 ciphertext (ASN.1 DER) with the corresponding
// private key.
func Decrypt(priv PrivateKey, data []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: nil private key")
	}
	if k, ok := priv.(*sm2PrivateKey); ok {
		return k.key.Decrypt(data)
	}
	return nil, fmt.Errorf("asym: Decrypt requires an SM2 key, got %s", priv.Algorithm())
}

// ---------------------------------------------------------------------------
// SM2 密文格式转换（C1C2C3 ↔ C1C3C2 ↔ DER）
// ---------------------------------------------------------------------------
//
// SM2 密文由 C1（椭圆曲线点）、C3（SM3 哈希，32 字节）、C2（密文，与明文等长）组成。
// 常见表示有三种：der / c1c3c2 / c1c2c3。
//
// SM2 ciphertexts comprise C1 (an EC point), C3 (the SM3 hash, 32 bytes)
// and C2 (the encrypted body, same length as plaintext). Three external
// representations are supported: der / c1c3c2 / c1c2c3.

// sm2Cipher 为 SM2 密文的规范中间表示（仅本文件内部使用）。
type sm2Cipher struct {
	c1   []byte // 原始 C1 点（65 未压缩 或 33 压缩）
	hash []byte // C3：32 字节
	c2   []byte // 密文
	x, y []byte // 未压缩点坐标（各 32 字节大端），仅未压缩点时有值
}

// Format 在 SM2 密文格式间转换。from/to 取值："der"、"c1c3c2"、"c1c2c3"。
//
// Format converts an SM2 ciphertext between representations. from and to
// must be one of "der", "c1c3c2", or "c1c2c3". When from == to a copy
// of ct is returned. Conversions involving "der" require an uncompressed
// C1 point.
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
		c, err = parseSM2DER(ct)
	case "c1c3c2", "c1c2c3":
		c, err = parseSM2Raw(ct, from == "c1c3c2")
	default:
		return nil, fmt.Errorf("asym: sm2: unknown ciphertext format %q (want der/c1c3c2/c1c2c3)", from)
	}
	if err != nil {
		return nil, err
	}
	switch to {
	case "der":
		return buildSM2DER(c)
	case "c1c3c2":
		return buildSM2Raw(c, true), nil
	case "c1c2c3":
		return buildSM2Raw(c, false), nil
	default:
		return nil, fmt.Errorf("asym: sm2: unknown ciphertext format %q (want der/c1c3c2/c1c2c3)", to)
	}
}

// EncryptWithOrder 使用 SM2 公钥加密，输出指定顺序的裸格式密文。
//
// EncryptWithOrder encrypts data with the SM2 public key and returns the
// raw-format ciphertext in the requested order. order must be "c1c3c2"
// (the default when empty) or "c1c2c3"; the returned C1 point is always
// uncompressed.
func EncryptWithOrder(pub PublicKey, data []byte, order string) ([]byte, error) {
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
//
// DecryptWithOrder decrypts a raw-format SM2 ciphertext in the given order.
// order must be "c1c3c2" (the default when empty) or "c1c2c3"; C1 must
// be an uncompressed point.
func DecryptWithOrder(priv PrivateKey, data []byte, order string) ([]byte, error) {
	if order == "" {
		order = "c1c3c2"
	}
	der, err := Format(data, order, "der")
	if err != nil {
		return nil, err
	}
	return Decrypt(priv, der)
}

func parseSM2DER(ct []byte) (*sm2Cipher, error) {
	var s struct {
		X    *big.Int
		Y    *big.Int
		Hash []byte
		CT   []byte
	}
	if _, err := asn1.Unmarshal(ct, &s); err != nil {
		return nil, fmt.Errorf("asym: sm2: invalid DER ciphertext: %w", err)
	}
	if s.X == nil || s.Y == nil {
		return nil, fmt.Errorf("asym: sm2: invalid DER ciphertext: missing coordinates")
	}
	x := s.X.Bytes()
	y := s.Y.Bytes()
	if len(x) > sm2CoordBytes || len(y) > sm2CoordBytes {
		return nil, fmt.Errorf("asym: sm2: invalid DER ciphertext: coordinate too large")
	}
	xb := make([]byte, sm2CoordBytes)
	yb := make([]byte, sm2CoordBytes)
	copy(xb[sm2CoordBytes-len(x):], x)
	copy(yb[sm2CoordBytes-len(y):], y)
	c1 := make([]byte, 0, sm2C1UncompressedLen)
	c1 = append(c1, sm2C1PrefixUncomp)
	c1 = append(c1, xb...)
	c1 = append(c1, yb...)
	return &sm2Cipher{c1: c1, hash: s.Hash, c2: s.CT, x: xb, y: yb}, nil
}

func buildSM2DER(c *sm2Cipher) ([]byte, error) {
	if c.x == nil || c.y == nil {
		return nil, fmt.Errorf("asym: sm2: cannot convert compressed C1 to DER")
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
		return nil, fmt.Errorf("asym: sm2: marshal DER ciphertext: %w", err)
	}
	return d, nil
}

func sm2C1Len(ct []byte) (int, error) {
	if len(ct) == 0 {
		return 0, fmt.Errorf("asym: sm2: empty ciphertext")
	}
	switch ct[0] {
	case sm2C1PrefixUncomp:
		return sm2C1UncompressedLen, nil
	case sm2C1PrefixCompEven, sm2C1PrefixCompOdd:
		return sm2C1CompressedLen, nil
	default:
		return 0, fmt.Errorf("asym: sm2: unsupported C1 point prefix 0x%02x", ct[0])
	}
}

func parseSM2Raw(ct []byte, hashFirst bool) (*sm2Cipher, error) {
	n, err := sm2C1Len(ct)
	if err != nil {
		return nil, err
	}
	if len(ct) < n+32 {
		return nil, fmt.Errorf("asym: sm2: ciphertext too short for C1+C3")
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

func buildSM2Raw(c *sm2Cipher, hashFirst bool) []byte {
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
