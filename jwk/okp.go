package jwk

import (
	"encoding/base64"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/sym"
)

// OKP 与对称密钥（`0.6.0` 新增）
//
// RFC 8037 扩展了 JWK 以表示 OKP 曲线（Ed25519 / Ed448 / X25519 / X448）：
// "x" 为**公钥原始字节**的 base64url，私钥的 "d" 为**种子原始字节**（Ed25519
// 为 32 字节，Ed448 为 57 字节；X25519 为 32 字节，X448 为 56 字节）。
//
// RFC 7518 §6.4 的对称密钥使用 Kty "oct" 与单个 "k" 字段（直接是密钥字节）。
//
// 注意：OKP 不适用 RSA/EC 的 PEM 往返路径（Go 标准库只认识 Ed25519），所以
// ToPEM / ToPublicPEM 在 OKP 上改走 `asym` 的 PEM 序列化，支持全部四种曲线。
//
// OKP and symmetric keys (added in `0.6.0`)
//
// RFC 8037 extends JWK to OKP curves (Ed25519 / Ed448 / X25519 / X448): "x"
// holds the **raw public key bytes** as base64url and, for private keys, "d"
// holds the **raw seed bytes** (32 for Ed25519, 57 for Ed448; 32 for X25519,
// 56 for X448).
//
// Symmetric keys follow RFC 7518 section 6.4: Kty "oct" with a single "k"
// field holding the key bytes directly.
//
// Note: OKP does not go through the RSA/EC PEM round-trip path (Go's standard
// library only knows Ed25519), so ToPEM / ToPublicPEM route OKP through
// `asym`'s PEM serialization instead, covering all four curves.

// OKP 曲线名（JWK "crv" 取值）。
//
// OKP curve names (the JWK "crv" values).
const (
	// CrvEd25519 为 Ed25519 曲线的 JWK 名。
	//
	// CrvEd25519 is the JWK name of the Ed25519 curve.
	CrvEd25519 = "Ed25519"
	// CrvEd448 为 Ed448 曲线的 JWK 名。
	//
	// CrvEd448 is the JWK name of the Ed448 curve.
	CrvEd448 = "Ed448"
	// CrvX25519 为 X25519 曲线的 JWK 名。
	//
	// CrvX25519 is the JWK name of the X25519 curve.
	CrvX25519 = "X25519"
	// CrvX448 为 X448 曲线的 JWK 名。
	//
	// CrvX448 is the JWK name of the X448 curve.
	CrvX448 = "X448"
)

// okpCrvByAlg 把 asym 算法标识映射为 JWK crv；非 OKP 返回 false。
//
// okpCrvByAlg maps an asym algorithm identifier to its JWK crv; it returns
// false for non-OKP algorithms.
func okpCrvByAlg(a asym.Algorithm) (string, bool) {
	switch a {
	case asym.AlgEd25519:
		return CrvEd25519, true
	case asym.AlgEd448:
		return CrvEd448, true
	case asym.AlgX25519:
		return CrvX25519, true
	case asym.AlgX448:
		return CrvX448, true
	}
	return "", false
}

// algByOKPCrv 把 JWK crv 映射为 asym 算法标识；未知返回错误。
//
// algByOKPCrv maps a JWK crv to its asym algorithm identifier; unknown
// values return an error.
func algByOKPCrv(crv string) (asym.Algorithm, error) {
	switch crv {
	case CrvEd25519:
		return asym.AlgEd25519, nil
	case CrvEd448:
		return asym.AlgEd448, nil
	case CrvX25519:
		return asym.AlgX25519, nil
	case CrvX448:
		return asym.AlgX448, nil
	}
	return "", fmt.Errorf("jwk: unknown OKP crv %q", crv)
}

// marshalOKP 把 OKP 密钥导出为 JWK（包内辅助）。
// 公钥写 "x"，私钥额外写 "d"（种子）。
//
// marshalOKP converts an OKP key into a JWK (package-internal helper). The
// public key goes into "x"; private keys also carry "d" (the seed).
func marshalOKP(k asym.Key) (*Key, error) {
	crv, ok := okpCrvByAlg(k.Algorithm())
	if !ok {
		return nil, fmt.Errorf("jwk: not an OKP key: %s", k.Algorithm())
	}
	pubKey, ok := k.(asym.PublicKey)
	if !ok {
		// 私钥对象只暴露 Public()，不直接实现 PublicKey 接口。
		priv, isPriv := k.(asym.PrivateKey)
		if !isPriv {
			return nil, fmt.Errorf("jwk: key %T exposes neither public nor private material", k)
		}
		pubKey = priv.Public()
	}
	pub, err := asym.RawPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("jwk: read public bytes: %w", err)
	}
	out := &Key{Kty: "OKP", Crv: crv, X: base64.RawURLEncoding.EncodeToString(pub)}
	if priv, ok := k.(asym.PrivateKey); ok {
		seed, serr := asym.RawPrivateKey(priv)
		if serr != nil {
			return nil, fmt.Errorf("jwk: read seed: %w", serr)
		}
		out.D = base64.RawURLEncoding.EncodeToString(seed)
	}
	return out, nil
}

// MarshalSymmetric 把对称密钥导出为 JWK（`Kty: "oct"`，密钥字节写入 "k"）。
//
// 安全：返回的 JWK 含明文密钥，调用方负责妥善处理（不要写日志）。
//
// MarshalSymmetric converts a symmetric key into a JWK (Kty "oct", key
// bytes in "k").
//
// Security: the returned JWK contains the raw key; callers must handle it
// accordingly (never log it).
func MarshalSymmetric(k sym.SymmetricKey) (*Key, error) {
	if k == nil {
		return nil, fmt.Errorf("jwk: nil symmetric key")
	}
	raw := k.Bytes()
	if len(raw) == 0 {
		return nil, fmt.Errorf("jwk: empty symmetric key")
	}
	return &Key{
		Kty: "oct",
		K:   base64.RawURLEncoding.EncodeToString(raw),
		Alg: string(k.Algorithm()),
	}, nil
}

// ToOKPKey 把 OKP JWK 还原为 asym 密钥：含 "d" 时返回私钥，否则返回公钥。
//
// 含私钥时，会用种子重新推导公钥并与 "x" 比对；不一致返回错误（避免静默接受
// 错配的 JWK）。
//
// ToOKPKey turns an OKP JWK back into an asym key: it returns a private key
// when "d" is present and a public key otherwise.
//
// When a private key is present the public key is re-derived from the seed
// and compared with "x"; a mismatch returns an error so a mismatched JWK is
// never silently accepted.
func (k *Key) ToOKPKey() (asym.Key, error) {
	if k == nil || k.Kty != "OKP" {
		return nil, fmt.Errorf("jwk: not an OKP key")
	}
	alg, err := algByOKPCrv(k.Crv)
	if err != nil {
		return nil, err
	}
	if k.D != "" {
		seed, derr := base64.RawURLEncoding.DecodeString(k.D)
		if derr != nil {
			return nil, fmt.Errorf("jwk: invalid base64url in d: %w", derr)
		}
		priv, gerr := asym.GenerateKeyFromSeed(alg, seed)
		if gerr != nil {
			return nil, fmt.Errorf("jwk: seed: %w", gerr)
		}
		if k.X != "" {
			want, xerr := base64.RawURLEncoding.DecodeString(k.X)
			if xerr != nil {
				return nil, fmt.Errorf("jwk: invalid base64url in x: %w", xerr)
			}
			got, berr := asym.RawPublicKey(priv.Public())
			if berr != nil {
				return nil, fmt.Errorf("jwk: read public bytes: %w", berr)
			}
			if string(got) != string(want) {
				return nil, fmt.Errorf("jwk: x does not match the private seed")
			}
		}
		return priv, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("jwk: invalid base64url in x: %w", err)
	}
	pub, err := asym.PublicKeyFromBytes(alg, raw)
	if err != nil {
		return nil, fmt.Errorf("jwk: public bytes: %w", err)
	}
	return pub, nil
}

// ToSymmetricKey 把 `Kty: "oct"` 的 JWK 还原为对称密钥。
// 按 "alg" 字段选择算法（AES-128 / AES-192 / AES-256 / SM4）；缺省时按
// 密钥长度推断（16 → SM4，24 → AES-192，32 → AES-256），无法推断返回错误。
//
// 安全：入参 JWK 与返回值均含明文密钥，调用方负责清零与保密。
//
// ToSymmetricKey turns a Kty "oct" JWK back into a symmetric key. The
// algorithm comes from the "alg" field (AES-128 / AES-192 / AES-256 / SM4);
// when absent it is inferred from the key length (16 → SM4, 24 → AES-192,
// 32 → AES-256), and an ambiguous length returns an error.
//
// Security: both the input JWK and the result carry the raw key; callers
// are responsible for zeroing and protecting it.
func (k *Key) ToSymmetricKey() (sym.SymmetricKey, error) {
	if k == nil || k.Kty != "oct" {
		return nil, fmt.Errorf("jwk: not an oct key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(k.K)
	if err != nil {
		return nil, fmt.Errorf("jwk: invalid base64url in k: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("jwk: empty symmetric key")
	}
	alg := sym.Algorithm(k.Alg)
	if alg == "" {
		switch len(raw) {
		case sym.SM4KeySize:
			alg = sym.AlgSM4
		case sym.AES192KeySize:
			alg = sym.AlgAES192
		case sym.AES256KeySize:
			alg = sym.AlgAES256
		default:
			return nil, fmt.Errorf("jwk: cannot infer symmetric algorithm from %d-byte key", len(raw))
		}
	}
	switch alg {
	case sym.AlgAES128, sym.AlgAES192, sym.AlgAES256:
		return sym.NewAESKey(raw)
	case sym.AlgSM4:
		return sym.NewSM4Key(raw)
	default:
		return nil, fmt.Errorf("jwk: unsupported symmetric algorithm %q", alg)
	}
}
