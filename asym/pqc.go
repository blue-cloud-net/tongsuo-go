package asym

import (
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

const (
	// AlgMLDSA44 表示 ML-DSA-44。
	//
	// AlgMLDSA44 identifies ML-DSA-44.
	AlgMLDSA44 Algorithm = "ML-DSA-44"

	// AlgMLDSA65 表示 ML-DSA-65。
	//
	// AlgMLDSA65 identifies ML-DSA-65.
	AlgMLDSA65 Algorithm = "ML-DSA-65"

	// AlgMLDSA87 表示 ML-DSA-87。
	//
	// AlgMLDSA87 identifies ML-DSA-87.
	AlgMLDSA87 Algorithm = "ML-DSA-87"

	// AlgSLHDSASHA2128S 表示 SLH-DSA-SHA2-128S。
	//
	// AlgSLHDSASHA2128S identifies SLH-DSA-SHA2-128S.
	AlgSLHDSASHA2128S Algorithm = "SLH-DSA-SHA2-128S"

	// AlgSLHDSASHA2128F 表示 SLH-DSA-SHA2-128F。
	//
	// AlgSLHDSASHA2128F identifies SLH-DSA-SHA2-128F.
	AlgSLHDSASHA2128F Algorithm = "SLH-DSA-SHA2-128F"

	// AlgSLHDSASHA2192S 表示 SLH-DSA-SHA2-192S。
	//
	// AlgSLHDSASHA2192S identifies SLH-DSA-SHA2-192S.
	AlgSLHDSASHA2192S Algorithm = "SLH-DSA-SHA2-192S"

	// AlgSLHDSASHA2192F 表示 SLH-DSA-SHA2-192F。
	//
	// AlgSLHDSASHA2192F identifies SLH-DSA-SHA2-192F.
	AlgSLHDSASHA2192F Algorithm = "SLH-DSA-SHA2-192F"

	// AlgSLHDSASHA2256S 表示 SLH-DSA-SHA2-256S。
	//
	// AlgSLHDSASHA2256S identifies SLH-DSA-SHA2-256S.
	AlgSLHDSASHA2256S Algorithm = "SLH-DSA-SHA2-256S"

	// AlgSLHDSASHA2256F 表示 SLH-DSA-SHA2-256F。
	//
	// AlgSLHDSASHA2256F identifies SLH-DSA-SHA2-256F.
	AlgSLHDSASHA2256F Algorithm = "SLH-DSA-SHA2-256F"

	// AlgSLHDSASHAKE128S 表示 SLH-DSA-SHAKE-128S。
	//
	// AlgSLHDSASHAKE128S identifies SLH-DSA-SHAKE-128S.
	AlgSLHDSASHAKE128S Algorithm = "SLH-DSA-SHAKE-128S"

	// AlgSLHDSASHAKE128F 表示 SLH-DSA-SHAKE-128F。
	//
	// AlgSLHDSASHAKE128F identifies SLH-DSA-SHAKE-128F.
	AlgSLHDSASHAKE128F Algorithm = "SLH-DSA-SHAKE-128F"

	// AlgSLHDSASHAKE192S 表示 SLH-DSA-SHAKE-192S。
	//
	// AlgSLHDSASHAKE192S identifies SLH-DSA-SHAKE-192S.
	AlgSLHDSASHAKE192S Algorithm = "SLH-DSA-SHAKE-192S"

	// AlgSLHDSASHAKE192F 表示 SLH-DSA-SHAKE-192F。
	//
	// AlgSLHDSASHAKE192F identifies SLH-DSA-SHAKE-192F.
	AlgSLHDSASHAKE192F Algorithm = "SLH-DSA-SHAKE-192F"

	// AlgSLHDSASHAKE256S 表示 SLH-DSA-SHAKE-256S。
	//
	// AlgSLHDSASHAKE256S identifies SLH-DSA-SHAKE-256S.
	AlgSLHDSASHAKE256S Algorithm = "SLH-DSA-SHAKE-256S"

	// AlgSLHDSASHAKE256F 表示 SLH-DSA-SHAKE-256F。
	//
	// AlgSLHDSASHAKE256F identifies SLH-DSA-SHAKE-256F.
	AlgSLHDSASHAKE256F Algorithm = "SLH-DSA-SHAKE-256F"

	// AlgMLKEM512 表示 ML-KEM-512。
	//
	// AlgMLKEM512 identifies ML-KEM-512.
	AlgMLKEM512 Algorithm = "ML-KEM-512"

	// AlgMLKEM768 表示 ML-KEM-768。
	//
	// AlgMLKEM768 identifies ML-KEM-768.
	AlgMLKEM768 Algorithm = "ML-KEM-768"

	// AlgMLKEM1024 表示 ML-KEM-1024。
	//
	// AlgMLKEM1024 identifies ML-KEM-1024.
	AlgMLKEM1024 Algorithm = "ML-KEM-1024"
)

func pqcVariant(alg Algorithm) bool {
	switch alg {
	case AlgMLDSA44, AlgMLDSA65, AlgMLDSA87,
		AlgSLHDSASHA2128S, AlgSLHDSASHA2128F, AlgSLHDSASHA2192S,
		AlgSLHDSASHA2192F, AlgSLHDSASHA2256S, AlgSLHDSASHA2256F,
		AlgSLHDSASHAKE128S, AlgSLHDSASHAKE128F, AlgSLHDSASHAKE192S,
		AlgSLHDSASHAKE192F, AlgSLHDSASHAKE256S, AlgSLHDSASHAKE256F,
		AlgMLKEM512, AlgMLKEM768, AlgMLKEM1024:
		return true
	default:
		return false
	}
}

type pqcKey struct {
	key *core.PKey
	alg Algorithm
}

type pqcPublicKey struct{ pqcKey }
type pqcPrivateKey struct{ pqcKey }

// Algorithm 返回密钥的 PQC 变体。
//
// Algorithm returns the key's PQC variant.
func (k pqcKey) Algorithm() Algorithm { return k.alg }

func (k pqcKey) corePKey() *core.PKey { return k.key }

// CorePKey 返回供 internal/keyaccess 复制的句柄。
//
// CorePKey returns the handle for internal/keyaccess to copy.
func (k pqcKey) CorePKey() *core.PKey { return k.key }

// Public 返回共享句柄的公钥。
//
// Public returns the public key sharing the same handle.
func (k *pqcPrivateKey) Public() PublicKey { return &pqcPublicKey{k.pqcKey} }

// MarshalPrivateKeyPEM 导出 PKCS#8 PEM，调用方负责清零输出。
//
// MarshalPrivateKeyPEM exports PKCS#8 PEM. The caller must wipe the output.
func (k *pqcPrivateKey) MarshalPrivateKeyPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalPublicKeyPEM 导出 SPKI PEM。
//
// MarshalPublicKeyPEM exports SPKI PEM.
func (k *pqcPublicKey) MarshalPublicKeyPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
}

// PQCAvailable 报告已知 PQC 变体在当前原生 provider 中是否可生成密钥。
//
// PQCAvailable reports whether the current native provider can generate keys for a known PQC variant.
func PQCAvailable(alg Algorithm) bool {
	alg = Algorithm(strings.ToUpper(string(alg)))
	return pqcVariant(alg) && core.PQCKeyAvailable(string(alg))
}
