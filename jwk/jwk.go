// Package jwk 实现 JSON Web Key（JWK）与 PEM 之间的转换。
//
// 支持 RSA（n/e/d/p/q/dp/dq/qi）与 EC（crv/x/y/d）密钥；base64url 无填充编码；
// PEM 与铜锁 openssl 互通（PKCS#8 / SPKI）。
package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Key 表示一个 JWK 密钥。
type Key struct {
	Kty string `json:"kty"` // "RSA" 或 "EC"
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`

	// RSA
	N  string `json:"n,omitempty"`
	E  string `json:"e,omitempty"`
	D  string `json:"d,omitempty"`
	P  string `json:"p,omitempty"`
	Q  string `json:"q,omitempty"`
	DP string `json:"dp,omitempty"`
	DQ string `json:"dq,omitempty"`
	QI string `json:"qi,omitempty"`

	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// Marshal 将核心密钥导出为 JWK。key 取自各密钥类型的 Key()（sm2/rsa/ecdsa 私钥或公钥）。
func Marshal(key *core.PKey) (*Key, error) {
	if key == nil {
		return nil, fmt.Errorf("jwk: nil key")
	}
	p := key.Params()
	if p == nil {
		return nil, fmt.Errorf("jwk: failed to read key params")
	}
	switch p.Type {
	case "RSA":
		k := &Key{Kty: "RSA"}
		if p.N != nil {
			k.N = b64(p.N)
		}
		if p.E != nil {
			k.E = b64(p.E)
		}
		if p.D != nil {
			k.D = b64(p.D)
		}
		if p.P != nil {
			k.P = b64(p.P)
		}
		if p.Q != nil {
			k.Q = b64(p.Q)
		}
		return k, nil
	case "EC", "SM2":
		k := &Key{Kty: "EC", Crv: crvName(p.Curve)}
		if p.X != nil {
			k.X = b64(p.X)
		}
		if p.Y != nil {
			k.Y = b64(p.Y)
		}
		if p.D != nil {
			k.D = b64(p.D)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("jwk: unsupported key type %q", p.Type)
	}
}

// Parse 解析 JWK JSON。
func Parse(data []byte) (*Key, error) {
	var k Key
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, fmt.Errorf("jwk: invalid JSON: %w", err)
	}
	switch k.Kty {
	case "RSA", "EC":
		return &k, nil
	default:
		return nil, fmt.Errorf("jwk: unsupported kty %q", k.Kty)
	}
}

// MarshalJSON 输出 JWK JSON。
func (k *Key) MarshalJSON() ([]byte, error) {
	type alias Key // 避免 Marshaler 递归
	return json.MarshalIndent((*alias)(k), "", "  ")
}

// IsPrivate 报告是否含私钥材料。
func (k *Key) IsPrivate() bool {
	return k.D != ""
}

// ToPEM 将 JWK 导出为 PEM（私钥 PKCS#8，公钥 SPKI）。
func (k *Key) ToPEM() ([]byte, error) {
	if !k.IsPrivate() {
		return k.ToPublicPEM()
	}
	var der []byte
	var err error
	switch k.Kty {
	case "RSA":
		priv, err2 := k.rsaPrivate()
		if err2 != nil {
			return nil, err2
		}
		der, err = stdx509.MarshalPKCS8PrivateKey(priv)
	case "EC":
		priv, err2 := k.ecPrivate()
		if err2 != nil {
			return nil, err2
		}
		der, err = stdx509.MarshalPKCS8PrivateKey(priv)
	default:
		return nil, fmt.Errorf("jwk: unsupported kty %q", k.Kty)
	}
	if err != nil {
		return nil, fmt.Errorf("jwk: marshal PKCS#8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ToPublicPEM 将 JWK 公钥导出为 PEM（SubjectPublicKeyInfo）。
func (k *Key) ToPublicPEM() ([]byte, error) {
	var pub any
	switch k.Kty {
	case "RSA":
		n, err := unb64(k.N)
		if err != nil {
			return nil, err
		}
		e, err := unb64(k.E)
		if err != nil {
			return nil, err
		}
		pub = &rsa.PublicKey{N: n, E: int(e.Int64())}
	case "EC":
		x, err := unb64(k.X)
		if err != nil {
			return nil, err
		}
		y, err := unb64(k.Y)
		if err != nil {
			return nil, err
		}
		curve, err := curveByName(k.Crv)
		if err != nil {
			return nil, err
		}
		pub = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	default:
		return nil, fmt.Errorf("jwk: unsupported kty %q", k.Kty)
	}
	der, err := stdx509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("jwk: marshal SPKI: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func (k *Key) rsaPrivate() (*rsa.PrivateKey, error) {
	n, err := unb64(k.N)
	if err != nil {
		return nil, err
	}
	e, err := unb64(k.E)
	if err != nil {
		return nil, err
	}
	d, err := unb64(k.D)
	if err != nil {
		return nil, err
	}
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
	}
	if k.P != "" && k.Q != "" {
		p, err1 := unb64(k.P)
		if err1 != nil {
			return nil, err1
		}
		q, err2 := unb64(k.Q)
		if err2 != nil {
			return nil, err2
		}
		priv.Primes = []*big.Int{p, q}
	}
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("jwk: invalid RSA key: %w", err)
	}
	priv.Precompute()
	return priv, nil
}

func (k *Key) ecPrivate() (*ecdsa.PrivateKey, error) {
	curve, err := curveByName(k.Crv)
	if err != nil {
		return nil, err
	}
	x, err := unb64(k.X)
	if err != nil {
		return nil, err
	}
	y, err := unb64(k.Y)
	if err != nil {
		return nil, err
	}
	d, err := unb64(k.D)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}, nil
}

// FromPEM 从 PEM（PKCS#8 / PKCS#1 私钥或 SPKI 公钥）构建 JWK。
func FromPEM(pemBytes []byte) (*Key, error) {
	var pk *core.PKey
	var err error
	pk, err = core.LoadPrivateKeyPEM(pemBytes)
	if err != nil {
		pk, err = core.LoadPrivateKeyPKCS1PEM(pemBytes)
	}
	if err != nil {
		pk, err = core.LoadPublicKeyPEM(pemBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("jwk: unsupported PEM: %v", err)
	}
	defer pk.Close()
	return Marshal(pk)
}

// b64 将大整数编码为 base64url（无填充）。
func b64(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

// unb64 解码 base64url（无填充）。
func unb64(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("jwk: invalid base64url: %w", err)
	}
	return new(big.Int).SetBytes(b), nil
}

// crvName 将曲线组名映射为 JWK crv。
func crvName(group string) string {
	switch group {
	case "prime256v1", "secp256r1":
		return "P-256"
	case "secp384r1":
		return "P-384"
	case "secp521r1":
		return "P-521"
	case "secp256k1":
		return "secp256k1"
	default:
		return group
	}
}

// curveByName 将 JWK crv 映射为椭圆曲线。
func curveByName(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	case "secp256k1":
		return nil, fmt.Errorf("jwk: curve %q not supported by stdlib", crv)
	default:
		return nil, fmt.Errorf("jwk: unknown curve %q", crv)
	}
}
