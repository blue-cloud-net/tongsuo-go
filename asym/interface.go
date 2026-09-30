package asym

import "github.com/blue-cloud-net/tongsuo-go/internal/core"

// Key 是所有非对称密钥（私钥 + 公钥）的通用接口。
// 仅描述「是什么算法」与「底层句柄的引用」（具体类型不可见）。
//
// Key is the common interface of every asymmetric key (private and
// public). It only exposes the algorithm identifier and a handle to the
// underlying native object; the concrete type stays hidden.
type Key interface {
	// Algorithm 返回该密钥的算法标识（见 Alg* 系列常量）。
	//
	// Algorithm returns the algorithm identifier (see the Alg* constants).
	Algorithm() Algorithm

	// corePKey 返回底层 *core.PKey，供同包内 SM2/RSA/EC 等专属函数使用；
	// 跨包访问通过 internal/keyaccess。
	//
	// corePKey returns the underlying *core.PKey, for use by the typed
	// helpers in this package (SM2 / RSA / EC etc.). Cross-package access
	// is mediated by internal/keyaccess.
	corePKey() *core.PKey
}

// PrivateKey 表示非对称私钥。
// 与 Key 相比增加 Public()：返回与本私钥配对的公钥（共享底层句柄）。
//
// PrivateKey represents an asymmetric private key. It extends Key with a
// Public method that returns the paired public key (sharing the underlying
// handle).
type PrivateKey interface {
	Key
	// Public 返回与该私钥配对的公钥（共享底层句柄）。
	//
	// Public returns the public key paired with this private key,
	// sharing the underlying handle.
	Public() PublicKey

	// MarshalPrivateKeyPEM 将私钥导出为 PKCS#8 PEM 块
	// （"-----BEGIN PRIVATE KEY-----"）。
	//
	// MarshalPrivateKeyPEM serializes the private key as a PKCS#8 PEM block.
	MarshalPrivateKeyPEM() ([]byte, error)
}

// PublicKey 表示非对称公钥。
//
// PublicKey represents an asymmetric public key.
type PublicKey interface {
	Key
	// MarshalPublicKeyPEM 将公钥导出为 SubjectPublicKeyInfo PEM 块
	// （"-----BEGIN PUBLIC KEY-----"）。
	//
	// MarshalPublicKeyPEM serializes the public key as a SPKI PEM block.
	MarshalPublicKeyPEM() ([]byte, error)
}
