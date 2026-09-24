// Package sm2 是 x509 遗留测试的迁移期替身，签名对齐已删除的 crypto/sm2。
//
// 仅测试使用；用法与删除时机见 internal/testutil/legacykeys 的包文档。
//
// Package sm2 is a migration-period stand-in for the legacy x509 tests, with
// signatures mirroring the removed crypto/sm2 package. Test-only; see the
// internal/testutil/legacykeys package documentation.
package sm2

import (
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil/legacykeys"
)

// PrivateKey 是 legacykeys.Key 的别名，对齐原 crypto/sm2.PrivateKey 的用法。
//
// PrivateKey aliases legacykeys.Key.
type PrivateKey = legacykeys.Key

// PublicKey 是 asym.PublicKey 的别名，对齐原 crypto/sm2.PublicKey 的用法。
//
// PublicKey aliases asym.PublicKey.
type PublicKey = asym.PublicKey

// GenerateKey 生成一把 SM2 私钥（等价原 crypto/sm2.GenerateKey）。
//
// GenerateKey generates an SM2 private key.
func GenerateKey() (*PrivateKey, error) {
	return legacykeys.Wrap(asym.GenerateSM2())
}

// Encrypt 用 SM2 公钥加密（默认 C1C3C2 顺序）。
//
// 参数直接是 asym.PublicKey：legacykeys 的包装类型不满足 asym.PublicKey（它只补了
// `Key()` / `CorePKey()`，没有 `MarshalPublicKeyPEM`），因此这里不会收到包装值。
//
// Encrypt encrypts data with an SM2 public key (default C1C3C2 ordering).
//
// The parameter is a plain asym.PublicKey: the legacykeys wrapper does not satisfy
// asym.PublicKey (it only adds Key() / CorePKey(), not MarshalPublicKeyPEM), so it
// can never be passed here.
func Encrypt(pub PublicKey, data []byte) ([]byte, error) {
	return asym.Encrypt(pub, data)
}

// Decrypt 用 SM2 私钥解密。
//
// 参数取指针：`legacykeys.Key` 的 `Public()` 是指针接收者，因此只有
// `*legacykeys.Key` 才满足 `asym.PrivateKey`。
//
// 先解包再转发：`asym.Decrypt` 内部对 `*sm2PrivateKey` 做具体类型断言，直接传入
// 包装值会报 "requires an SM2 key"。
//
// Decrypt decrypts data with an SM2 private key.
//
// The parameter is a pointer because legacykeys.Key's Public has a pointer
// receiver, so only *legacykeys.Key satisfies asym.PrivateKey. It unwraps before
// forwarding: asym.Decrypt asserts on the concrete *sm2PrivateKey type, so a
// wrapped value would be rejected with "requires an SM2 key".
func Decrypt(priv *PrivateKey, data []byte) ([]byte, error) {
	if priv == nil {
		return asym.Decrypt(nil, data)
	}
	return asym.Decrypt(priv.PrivateKey, data)
}
