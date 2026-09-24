package asym

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// NIST / SEC 标准曲线的铜锁名。
// ECDSA 生成时的 curve 参数直接透传给铜锁 EVP 管线，下列常量为常用曲线的
// 规范名；也可直接传其它铜锁可识别的曲线名（如 "secp224r1"）。
//
// Tongsuo curve names for the NIST / SEC standard curves. The curve
// argument of the ECDSA generators is forwarded verbatim to the Tongsuo
// EVP pipeline, so the constants below are the canonical spellings of
// the common curves; any other Tongsuo-recognised curve name (such as
// "secp224r1") may be passed as well.
const (
	CurveP256      = "prime256v1" // NIST P-256（亦称 secp256r1）
	CurveP384      = "secp384r1"  // NIST P-384
	CurveP521      = "secp521r1"  // NIST P-521
	CurveSecp256k1 = "secp256k1"  // SEC 2（比特币等生态常用）
)

// sm2CurveNames 是 ECDSA 入口明确拒绝的曲线名。
// SM2 曲线在 asym 中有专属入口（GenerateSM2 等），
// 其密钥算法标识为 AlgSM2；此处拒绝以免同一个 SM2 密钥存在两种表示。
//
// sm2CurveNames lists the curve names the ECDSA entry points reject.
// The SM2 curve has dedicated entry points in asym (GenerateSM2,
// LoadSM2PrivateKeyPEM-style loaders) and its keys report AlgSM2;
// here avoids two representations of the same SM2 key.
var sm2CurveNames = map[string]bool{
	"sm2":       true,
	"sm2p256v1": true,
}

// ecPrivateKey 是 ECDSA 私钥的具体类型（非导出）。
//
// ecPrivateKey is the concrete (unexported) type for ECDSA private keys.
type ecPrivateKey struct {
	key *core.PKey
}

// ecPublicKey 是 ECDSA 公钥的具体类型（非导出）。
//
// ecPublicKey is the concrete (unexported) type for ECDSA public keys.
type ecPublicKey struct {
	key *core.PKey
}

// Algorithm 实现 Key 接口。
func (k *ecPrivateKey) Algorithm() Algorithm { return AlgEC }

// Algorithm 实现 Key 接口。
func (k *ecPublicKey) Algorithm() Algorithm { return AlgEC }

// corePKey 实现 Key 接口。
func (k *ecPrivateKey) corePKey() *core.PKey { return k.key }

// corePKey 实现 Key 接口。
func (k *ecPublicKey) corePKey() *core.PKey { return k.key }

// Public 返回配对的公钥（共享底层 core.PKey）。
func (k *ecPrivateKey) Public() PublicKey {
	return &ecPublicKey{key: k.key}
}

// MarshalPrivateKeyPEM 导出为 PKCS#8 PEM。
func (k *ecPrivateKey) MarshalPrivateKeyPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalPublicKeyPEM 导出为 SubjectPublicKeyInfo PEM。
func (k *ecPublicKey) MarshalPublicKeyPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
}

// GenerateEC 生成指定曲线的 ECDSA 密钥对。
// curve 不能为空，取值见 CurveP256 / CurveP384 / CurveP521 / CurveSecp256k1；
// 传 SM2 曲线名（"sm2" / "sm2p256v1"）将被拒绝，请改用 GenerateSM2。
//
// GenerateEC generates an ECDSA key pair on the given curve. curve must
// be non-empty; see CurveP256 / CurveP384 / CurveP521 / CurveSecp256k1.
// The SM2 curve names ("sm2" / "sm2p256v1") are rejected — use
// GenerateSM2 instead.
func GenerateEC(curve string) (PrivateKey, error) {
	if curve == "" {
		return nil, fmt.Errorf("asym: ec: empty curve name")
	}
	if sm2CurveNames[curve] {
		return nil, fmt.Errorf("asym: ec: curve %q is SM2; use GenerateSM2", curve)
	}
	k, err := core.GenerateECKey(curve)
	if err != nil {
		return nil, err
	}
	return &ecPrivateKey{key: k}, nil
}

// SignECDSA 使用 ECDSA-SHA256 对 data 签名，返回 ASN.1 DER 签名。
// 摘要固定为 SHA-256（由铜锁 EVP 管线决定）；需要其它摘要的调用方须自行
// 预哈希后再调用。
//
// SignECDSA produces an ECDSA-SHA256 signature over data and returns it
// in ASN.1 DER encoding. The digest is fixed to SHA-256 by the Tongsuo
// EVP pipeline; callers who need a different digest must hash the data
// themselves first.
func SignECDSA(priv PrivateKey, data []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: ec: nil private key")
	}
	if priv.Algorithm() != AlgEC {
		return nil, fmt.Errorf("asym: ec: SignECDSA requires an EC key, got %s", priv.Algorithm())
	}
	return priv.corePKey().SignDigest(data, core.SHA256())
}

// VerifyECDSA 使用 ECDSA-SHA256 验签（签名须为 ASN.1 DER）。
// 验签失败返回错误（不返回布尔值）；调用方须将任意非 nil 错误视为认证失败。
//
// VerifyECDSA checks an ECDSA-SHA256 signature. The signature must be
// ASN.1 DER. Returns an error (never a boolean) on failure; callers must
// treat any non-nil error as authentication failure.
func VerifyECDSA(pub PublicKey, data, sig []byte) error {
	if pub == nil {
		return fmt.Errorf("asym: ec: nil public key")
	}
	if pub.Algorithm() != AlgEC {
		return fmt.Errorf("asym: ec: VerifyECDSA requires an EC key, got %s", pub.Algorithm())
	}
	return pub.corePKey().VerifyDigest(data, sig, core.SHA256())
}
