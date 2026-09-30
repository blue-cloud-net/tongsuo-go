package asym

import (
	"fmt"
	"math/big"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// KeyParams 是算法的公开参数快照（不依赖任何 internal 类型）。
//
// 各字段按算法填充：
//
//	RSA         N / E / D / P / Q / Dmp1 / Dmq1 / Iqmp
//	EC / SM2    Curve / X / Y / D
//	Ed25519 等  Type 仅为算法名，数值字段留空（请改用 RawPrivateKey / RawPublicKey）
//
// 公钥视图仅填充公开分量；私钥视图额外填充私钥分量。注意若公钥由私钥的
// Public() 取得（共享底层句柄），其 D 等私钥分量同样可见——需要「仅公开分量」
// 的快照时，请从 SPKI PEM 独立加载公钥后再调用 Params。
//
// KeyParams is a public parameter snapshot of a key that does not depend
// on any internal type.
//
// The fields are populated per algorithm:
//
//	RSA         N / E / D / P / Q / Dmp1 / Dmq1 / Iqmp
//	EC / SM2    Curve / X / Y / D
//	Ed25519 et al. only Type carries the algorithm name; the numeric
//	               fields stay nil (use RawPrivateKey / RawPublicKey)
//
// A public-key view fills only the public components while a private-key
// view additionally fills the private ones. Note that a public key obtained
// from a private key's Public() shares the underlying handle, so private
// components such as D remain visible; for a public-only snapshot, load the
// public key independently from SPKI PEM and then call Params.
type KeyParams struct {
	Type string // "RSA" / "EC" / "SM2" / "ED25519" / ...

	N *big.Int // RSA 模数
	E *big.Int // RSA 公钥指数
	D *big.Int // RSA 私钥指数 / EC（含 SM2）私钥标量
	P *big.Int // RSA 素因子 p（PKCS#1 记法）
	Q *big.Int // RSA 素因子 q（PKCS#1 记法）

	Dmp1 *big.Int // RSA CRT：dmp1 = d mod (p-1)
	Dmq1 *big.Int // RSA CRT：dmq1 = d mod (q-1)
	Iqmp *big.Int // RSA CRT：iqmp = q⁻¹ mod p

	Curve string   // EC（含 SM2）曲线名（如 "prime256v1"）
	X     *big.Int // EC 公钥点 X
	Y     *big.Int // EC 公钥点 Y
}

// keyParamsFromCore 把 core.KeyParams 复制为公开的 KeyParams。
// 仅复制数值引用（*big.Int 为不可变使用约定，调用方不应就地修改）。
//
// keyParamsFromCore copies a core.KeyParams into the public KeyParams.
// Big integers are copied by reference, following the convention that
// *big.Int values are treated as immutable by callers.
func keyParamsFromCore(kp *core.KeyParams) *KeyParams {
	if kp == nil {
		return nil
	}
	return &KeyParams{
		Type:  kp.Type,
		N:     kp.N,
		E:     kp.E,
		D:     kp.D,
		P:     kp.P,
		Q:     kp.Q,
		Dmp1:  kp.Dmp1,
		Dmq1:  kp.Dmq1,
		Iqmp:  kp.Iqmp,
		Curve: kp.Curve,
		X:     kp.X,
		Y:     kp.Y,
	}
}

// Params 返回密钥的公开参数快照（算法无关）。
// key 可为私钥或公钥；nil 时返回错误。
// 解析出的参数由底层铜锁决定，未涉及的分量为 nil。
//
// Params returns a public parameter snapshot of the key, regardless of
// algorithm. key may be a private or a public key; nil yields an error.
// Which fields carry values is decided by Tongsuo; unrelated fields are
// nil.
func Params(key Key) (*KeyParams, error) {
	if key == nil {
		return nil, fmt.Errorf("asym: nil key")
	}
	return keyParamsFromCore(key.corePKey().Params()), nil
}

// Match 判断私钥的公钥分量是否与给定公钥一致（算法无关，nil-safe）。
// 不一致或任一侧为 nil 时返回 false。
//
// 典型用途：校验证书携带的公钥是否与本私钥配对。
//
// Match reports whether the public component of priv equals pub,
// regardless of algorithm (nil-safe). It returns false when the keys do
// not match or when either side is nil.
//
// A typical use is checking whether a certificate's public key pairs with
// a given private key.
func Match(priv PrivateKey, pub PublicKey) (bool, error) {
	if priv == nil || pub == nil {
		return false, nil
	}
	privKey := priv.corePKey()
	pubKey := pub.corePKey()
	if privKey == nil || pubKey == nil {
		return false, nil
	}
	return privKey.PublicEqual(pubKey), nil
}
