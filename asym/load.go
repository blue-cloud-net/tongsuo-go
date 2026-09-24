package asym

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// wrapPrivateKey 按底层算法把 *core.PKey 包装为对应的非导出私钥类型。
// 未知算法返回 ErrUnknownAlgorithm 的包装错误（调用方负责释放 k）。
//
// wrapPrivateKey wraps a *core.PKey into the concrete (unexported) private
// key type matching its underlying algorithm. Unknown algorithms produce
// an error wrapping ErrUnknownAlgorithm; the caller keeps ownership of k
// on failure.
func wrapPrivateKey(k *core.PKey) (PrivateKey, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: nil key handle", ErrInvalidKey)
	}
	switch k.Algorithm() {
	case string(AlgSM2):
		return &sm2PrivateKey{key: k}, nil
	case string(AlgRSA):
		return &rsaPrivateKey{key: k}, nil
	case string(AlgEC):
		return &ecPrivateKey{key: k}, nil
	case string(AlgEd25519):
		return &ed25519PrivateKey{key: k}, nil
	case string(AlgEd448):
		return &ed448PrivateKey{key: k}, nil
	default:
		return nil, fmt.Errorf("%w: private key algorithm %q", ErrUnknownAlgorithm, k.Algorithm())
	}
}

// wrapPublicKey 按底层算法把 *core.PKey 包装为对应的非导出公钥类型。
// 未知算法返回 ErrUnknownAlgorithm 的包装错误（调用方负责释放 k）。
//
// wrapPublicKey wraps a *core.PKey into the concrete (unexported) public
// key type matching its underlying algorithm. Unknown algorithms produce
// an error wrapping ErrUnknownAlgorithm; the caller keeps ownership of k
// on failure.
func wrapPublicKey(k *core.PKey) (PublicKey, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: nil key handle", ErrInvalidKey)
	}
	switch k.Algorithm() {
	case string(AlgSM2):
		return &sm2PublicKey{key: k}, nil
	case string(AlgRSA):
		return &rsaPublicKey{key: k}, nil
	case string(AlgEC):
		return &ecPublicKey{key: k}, nil
	case string(AlgEd25519):
		return &ed25519PublicKey{key: k}, nil
	case string(AlgEd448):
		return &ed448PublicKey{key: k}, nil
	default:
		return nil, fmt.Errorf("%w: public key algorithm %q", ErrUnknownAlgorithm, k.Algorithm())
	}
}

// LoadPrivateKeyPEM 按 PEM 块自动识别算法加载私钥。
// 接受 PKCS#8（"BEGIN PRIVATE KEY"）、传统 PKCS#1（"BEGIN RSA PRIVATE KEY"）
// 与 SEC1（"BEGIN EC PRIVATE KEY"）三种编码——底层 PEM_read_bio_PrivateKey
// 统一处理，无需调用方指定算法。
// 加载后按底层算法返回对应具体类型；未知算法返回 ErrUnknownAlgorithm。
//
// 安全：解析后的私钥仅存在于铜锁 C 端 EVP_PKEY 中，Go 侧不持有副本；
// **调用方有责任在使用完毕后清零 PEM 源缓冲区**。
//
// LoadPrivateKeyPEM loads a private key from a PEM block, detecting the
// algorithm automatically. It accepts PKCS#8 ("BEGIN PRIVATE KEY"), legacy
// PKCS#1 ("BEGIN RSA PRIVATE KEY") and SEC1 ("BEGIN EC PRIVATE KEY")
// encodings — the underlying PEM_read_bio_PrivateKey handles all three, so
// callers need not know the algorithm up front. The returned value is the
// concrete type matching the embedded algorithm; unknown algorithms yield
// an error wrapping ErrUnknownAlgorithm.
//
// Security: the parsed private key lives only in the Tongsuo-side EVP_PKEY
// structure and is never copied into Go memory. The caller is responsible
// for zeroising the source PEM buffer after use.
func LoadPrivateKeyPEM(pem []byte) (PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	priv, werr := wrapPrivateKey(k)
	if werr != nil {
		k.Close()
		return nil, werr
	}
	return priv, nil
}

// LoadEncryptedPrivateKeyPEM 按 PEM 块自动识别算法加载加密私钥
// （AES-256-CBC + PBKDF2，块头 "BEGIN ENCRYPTED PRIVATE KEY"）。
// pass 为口令；口令错误或算法未知时返回错误。
//
// LoadEncryptedPrivateKeyPEM loads an encrypted private key from a PEM
// block (AES-256-CBC + PBKDF2, "BEGIN ENCRYPTED PRIVATE KEY"), detecting
// the algorithm automatically. pass is the passphrase.
func LoadEncryptedPrivateKeyPEM(pem []byte, pass string) (PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEMEncrypted(pem, pass)
	if err != nil {
		return nil, err
	}
	priv, werr := wrapPrivateKey(k)
	if werr != nil {
		k.Close()
		return nil, werr
	}
	return priv, nil
}

// LoadPublicKeyPEM 按 PEM 块自动识别算法加载公钥
// （SubjectPublicKeyInfo，"BEGIN PUBLIC KEY"）。
// 加载后按底层算法返回对应具体类型；未知算法返回 ErrUnknownAlgorithm。
//
// LoadPublicKeyPEM loads a public key from a SubjectPublicKeyInfo PEM
// block ("BEGIN PUBLIC KEY"), detecting the algorithm automatically.
// Unknown algorithms yield an error wrapping ErrUnknownAlgorithm.
func LoadPublicKeyPEM(pem []byte) (PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	pub, werr := wrapPublicKey(k)
	if werr != nil {
		k.Close()
		return nil, werr
	}
	return pub, nil
}

// ChangePassword 读取旧口令加密的私钥 PEM 并导出为新口令加密（算法无关）。
// oldPass 解密失败或重加密失败时返回错误。
//
// ChangePassword decrypts an encrypted private-key PEM with oldPass and
// returns a freshly encrypted PEM under newPass. It is algorithm-agnostic
// and returns an error when oldPass fails to decrypt the input or when
// re-encryption fails.
func ChangePassword(pemBytes []byte, oldPass, newPass string) ([]byte, error) {
	return core.ChangePrivateKeyPassword(pemBytes, oldPass, newPass)
}

// MarshalEncryptedPrivateKeyPEM 用口令加密导出私钥为 PEM（AES-256-CBC + PBKDF2）。
// 与算法无关；私钥对应 PKCS#8 的加密编码（"BEGIN ENCRYPTED PRIVATE KEY"）。
//
// MarshalEncryptedPrivateKeyPEM encodes any private key as an encrypted
// PKCS#8 PEM block ("BEGIN ENCRYPTED PRIVATE KEY") using AES-256-CBC with
// a PBKDF2-derived key.
func MarshalEncryptedPrivateKeyPEM(priv PrivateKey, pass string) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: nil private key")
	}
	return priv.corePKey().MarshalEncryptedPEM(pass)
}

// MarshalEncryptedPrivateKeyPEMWithCipher 用指定 cipher 加密导出私钥为 PEM。
// cipher 取 OpenSSL 通用名（如 "aes-128-cbc"、"aes-256-cbc"、"des-ede3-cbc"）；
// cipher == "" 与 MarshalEncryptedPrivateKeyPEM 等价（AES-256-CBC 兜底）。
// AEAD cipher（如 AES-GCM）不被 PKCS#8 PBES2 接受，调用将失败。
//
// MarshalEncryptedPrivateKeyPEMWithCipher encodes any private key as an
// encrypted PEM block using the given cipher (OpenSSL generic name, e.g.
// "aes-128-cbc", "aes-256-cbc", "des-ede3-cbc"). An empty cipher matches
// MarshalEncryptedPrivateKeyPEM (AES-256-CBC). AEAD ciphers such as
// AES-GCM are rejected by PKCS#8 PBES2.
func MarshalEncryptedPrivateKeyPEMWithCipher(priv PrivateKey, cipher, pass string) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: nil private key")
	}
	return priv.corePKey().MarshalEncryptedPEMWithCipher(cipher, pass)
}
