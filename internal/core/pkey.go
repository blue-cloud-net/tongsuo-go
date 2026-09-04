package core

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"math/big"
	"runtime"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// DefaultSM2ID 为 SM2 算法默认用户标识（GM/T 0003-2012）。
//
// 默认值即 ASCII 字符串 "1234567812345678"，在 Sign/Verify 未显式传入 id 时使用；该值由铜锁推荐用于 SM2withSM3 签名。
//
// DefaultSM2ID is the default user identifier for the SM2 algorithm (GM/T 0003-2012).
//
// It holds the exact ASCII bytes "1234567812345678" and is used as the
// default user ID argument by Sign and Verify when none is supplied.
// This is the value recommended by Tongsuo for SM2withSM3 signatures.
var DefaultSM2ID = []byte("1234567812345678")

// PKey 表示一个非对称密钥对象（EVP_PKEY 的包装）。
//
// 当前用于 SM2，后续阶段会扩展到 RSA / EC；通过内部 Handle 持有底层 EVP_PKEY，使用完毕须调用 Close 释放。
//
// PKey is the Go wrapper around an OpenSSL EVP_PKEY asymmetric key.
//
// The type is currently used for SM2 and will be extended to RSA / EC in
// later stages. It owns the underlying EVP_PKEY handle through an internal
// Handle value; callers must invoke Close to release the key once they are
// done using it.
type PKey struct {
	handle *Handle
}

// BaseID 返回密钥底层类型 ID（如 native.EvpPkeyEC）。
//
// 方法可安全用于 nil 接收者或已关闭的密钥——这两种情况均返回 native.NidUndef；否则返回 EVP_PKEY_get_base_id 的结果。
//
// BaseID returns the EVP_PKEY base type ID of the underlying key
// (for example native.EvpPkeyEC).
//
// The method is safe to call on a nil receiver or on an already-closed key:
// in both cases it returns native.NidUndef. Otherwise it returns the value
// produced by EVP_PKEY_get_base_id.
func (k *PKey) BaseID() int {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return native.NidUndef
	}
	return native.EVP_PKEY_get_base_id(k.handle.Ptr())
}

// TypeID 返回密钥完整类型 ID（如 SM2 密钥返回 native.EvpPkeySM2）。
//
// 方法可安全用于 nil 接收者或已关闭的密钥——这两种情况均返回 native.NidUndef；否则返回 EVP_PKEY_get_id 的结果。
//
// TypeID returns the full EVP_PKEY type ID of the underlying key
// (for example native.EvpPkeySM2 for an SM2 key).
//
// The method is safe to call on a nil receiver or on an already-closed key:
// in both cases it returns native.NidUndef. Otherwise it returns the value
// produced by EVP_PKEY_get_id.
func (k *PKey) TypeID() int {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return native.NidUndef
	}
	return native.EVP_PKEY_get_id(k.handle.Ptr())
}

// Algorithm 返回密钥算法名（如 "SM2"、"RSA"、"EC"）；未知返回 "id:<n>"。
//
// 在 Tongsuo / OpenSSL 3.x 中 EC 密钥的 base ID 为 EVP_PKEY_EC，因此需检查完整类型 ID 以区分 SM2（EVP_PKEY_SM2）与普通 EC；方法可安全用于 nil 接收者。
//
// Algorithm returns the human-readable algorithm name of the underlying key
// (for example "SM2", "RSA", or "EC"); unknown types return "id:<n>".
//
// For EC keys on Tongsuo / OpenSSL 3.x the base ID is EVP_PKEY_EC, so the
// full type ID is inspected to distinguish SM2 (which reports EVP_PKEY_SM2)
// from generic EC. The method is safe to call on a nil receiver.
func (k *PKey) Algorithm() string {
	// 铜锁/OpenSSL 3.x 中 SM2 密钥的 base id 为 EC（EVP_PKEY_EC），
	// 需用完整类型 id（EVP_PKEY_SM2）区分。
	if k.BaseID() == native.EvpPkeyEC {
		if k.TypeID() == native.EvpPkeySM2 {
			return "SM2"
		}
		return "EC"
	}
	switch k.BaseID() {
	case native.EvpPkeySM2:
		return "SM2"
	case native.EvpPkeyRSA:
		return "RSA"
	case native.EvpPkeyDSA:
		return "DSA"
	default:
		return fmt.Sprintf("id:%d", k.BaseID())
	}
}

// GenerateSM2Key 生成新的 SM2 密钥对（基于 EVP_PKEY_Q_keygen）。
//
// 返回的 *PKey 持有底层 EVP_PKEY，使用完毕须调用 Close 释放；若底层原生调用失败（例如未加载 SM2 provider），返回的错误包装来自 native.PopError 的 OpenSSL 错误码。
//
// GenerateSM2Key generates a fresh SM2 key pair using EVP_PKEY_Q_keygen.
//
// The returned *PKey owns the underlying EVP_PKEY and the caller is
// responsible for calling Close to release it. If the underlying native
// call fails (for example because no SM2 provider is available), the
// returned error wraps the OpenSSL error code from native.PopError.
func GenerateSM2Key() (*PKey, error) {
	p := native.X_EVP_PKEY_Q_keygen_sm2()
	if p == nil {
		return nil, NewOpError("pkey: EVP_PKEY_Q_keygen(SM2)", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// LoadPrivateKeyPEM 从 PEM（PKCS#8）加载密钥（私钥）。
//
// 同时接受未加密 PKCS#8（"-----BEGIN PRIVATE KEY-----"）与加密 PKCS#8（"-----BEGIN ENCRYPTED PRIVATE KEY-----"）；基于口令的传统 PEM 格式请改用 LoadPrivateKeyPEMEncrypted。返回的 *PKey 持有底层 EVP_PKEY，使用完毕须调用 Close 释放。
//
// LoadPrivateKeyPEM loads a private key from PKCS#8 PEM data.
//
// It accepts both unencrypted PKCS#8 blocks ("-----BEGIN PRIVATE KEY-----")
// and encrypted PKCS#8 blocks ("-----BEGIN ENCRYPTED PRIVATE KEY-----");
// for password-based legacy PEM formats use LoadPrivateKeyPEMEncrypted
// instead. The returned *PKey owns the underlying EVP_PKEY and the caller
// must invoke Close to release it.
func LoadPrivateKeyPEM(pem []byte) (*PKey, error) {
	return loadPEM("pkey: PEM_read_bio_PrivateKey", native.X_PEM_read_bio_PrivateKey, pem)
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载密钥（公钥）。
//
// 返回的 *PKey 持有底层 EVP_PKEY，使用完毕须调用 Close 释放；失败时错误以 OpError 形式包装，并携带底层 OpenSSL 错误码。
//
// LoadPublicKeyPEM loads a public key from a SubjectPublicKeyInfo (SPKI)
// PEM block ("-----BEGIN PUBLIC KEY-----").
//
// The returned *PKey owns the underlying EVP_PKEY and the caller must
// invoke Close to release it. Errors are wrapped as OpError and contain
// the underlying OpenSSL error code.
func LoadPublicKeyPEM(pem []byte) (*PKey, error) {
	return loadPEM("pkey: PEM_read_bio_PUBKEY", native.X_PEM_read_bio_PUBKEY, pem)
}

// loadPEM 从 PEM 字节流读取并构造 *PKey。
//
// loadPEM decodes a PEM-encoded key from pem using the supplied
// OpenSSL reader and returns a *PKey. On failure it returns an error
// wrapping an OpError that names the underlying OpenSSL operation.
func loadPEM(op string, read func(bio unsafe.Pointer) unsafe.Pointer, pem []byte) (*PKey, error) {
	bio := native.BIO_new_mem_buf(pem)
	if bio == nil {
		return nil, NewOpError(op+"(BIO_new_mem_buf)", native.PopError())
	}
	defer native.BIO_free(bio)
	p := read(bio)
	if p == nil {
		return nil, NewOpError(op, native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// MarshalPrivateKeyPEM 将密钥导出为 PEM（PKCS#8）。
//
// 基于口令的加密场景请改用 MarshalEncryptedPEM；若密钥已通过 Close 释放，或底层 OpenSSL 写失败，均返回包装为 OpError 的错误。
//
// MarshalPrivateKeyPEM serializes the private key to an unencrypted
// PKCS#8 PEM block ("-----BEGIN PRIVATE KEY-----").
//
// For password-based encryption use MarshalEncryptedPEM instead. Returns
// an error if the key has been closed via Close, or if the underlying
// OpenSSL write fails (errors are wrapped as OpError).
func (k *PKey) MarshalPrivateKeyPEM() ([]byte, error) {
	return k.marshalPEM("pkey: PEM_write_bio_PrivateKey", native.X_PEM_write_bio_PrivateKey)
}

// MarshalPublicKeyPEM 将公钥导出为 PEM（SubjectPublicKeyInfo）。
//
// 若密钥已通过 Close 释放，或底层 OpenSSL 写失败，均返回包装为 OpError 的错误。
//
// MarshalPublicKeyPEM serializes the public key to a SubjectPublicKeyInfo
// (SPKI) PEM block ("-----BEGIN PUBLIC KEY-----").
//
// Returns an error if the key has been closed via Close, or if the
// underlying OpenSSL write fails (errors are wrapped as OpError).
func (k *PKey) MarshalPublicKeyPEM() ([]byte, error) {
	return k.marshalPEM("pkey: PEM_write_bio_PUBKEY", native.X_PEM_write_bio_PUBKEY)
}

// marshalPEM 将 *PKey 序列化为 PEM 字节流。
//
// marshalPEM writes the key to a memory BIO using the supplied OpenSSL
// writer and returns the PEM bytes. On failure it returns an error
// wrapping an OpError that names the underlying OpenSSL operation.
func (k *PKey) marshalPEM(op string, write func(bio, pkey unsafe.Pointer) bool) ([]byte, error) {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return nil, fmt.Errorf("pkey: key closed")
	}
	bio := native.BIO_new(native.BIO_s_mem())
	if bio == nil {
		return nil, NewOpError(op+"(BIO_new)", native.PopError())
	}
	defer native.BIO_free(bio)
	if !write(bio, k.handle.Ptr()) {
		return nil, NewOpError(op, native.PopError())
	}
	var out []byte
	tmp := make([]byte, 1024)
	for {
		n := native.BIO_read(bio, tmp)
		if n <= 0 {
			break
		}
		out = append(out, tmp[:n]...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pkey: empty PEM output")
	}
	return out, nil
}

// Encrypt 使用公钥加密数据。
//
// 注意：Tongsuo 8.x（OpenSSL 3.x）SM2 加密输出为 ASN.1 DER 编码（内含 C1C3C2），
// 与 openssl pkeyutl 输出一致；方法会锁定当前 OS 线程（Tongsuo SM2 provider 对线程敏感）。
// 空明文支持由各算法决定：SM2 不支持空明文（见 crypto/sm2.Encrypt 的公开层检查），
// RSA PKCS#1 v1.5 / OAEP 允许空明文（与 Go 标准库 rsa 一致）——本通用路径不做
// 空明文拒绝，交由底层 EVP_PKEY_CTX 与上层算法封装决定。
//
// Encrypt encrypts data using the public key.
//
// Note: on Tongsuo 8.x (OpenSSL 3.x) the SM2 ciphertext is encoded as ASN.1
// DER (with the inner C1C3C2 layout), which is identical to the output of
// `openssl pkeyutl -encrypt`. The method locks the current OS thread
// because the Tongsuo SM2 provider is thread-sensitive. Empty-plaintext
// policy is left to each algorithm: SM2 rejects it (see the check in
// crypto/sm2.Encrypt), while RSA PKCS#1 v1.5 / OAEP accept it (matching
// the Go stdlib rsa package). This shared path does not reject empty
// input; the underlying EVP_PKEY_CTX and the algorithm wrapper decide.
func (k *PKey) Encrypt(data []byte) ([]byte, error) {
	// 同一密钥上下文的多次 cgo 调用需固定到同一 OS 线程（Tongsuo SM2 provider 对线程敏感）。
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx := native.EVP_PKEY_CTX_new_from_pkey(k.handle.Ptr())
	if ctx == nil {
		return nil, NewOpError("pkey: EVP_PKEY_CTX_new_from_pkey", native.PopError())
	}
	defer native.EVP_PKEY_CTX_free(ctx)
	if !native.EVP_PKEY_encrypt_init(ctx) {
		return nil, NewOpError("pkey: EVP_PKEY_encrypt_init", native.PopError())
	}
	// 首次调用为长度查询（Tongsuo 8.5 provider 行为），随后分配缓冲并实际加密。
	var outlen int
	if !native.EVP_PKEY_encrypt(ctx, nil, data, &outlen) {
		return nil, NewOpError("pkey: EVP_PKEY_encrypt(size)", native.PopError())
	}
	out := make([]byte, outlen)
	if !native.EVP_PKEY_encrypt(ctx, out, data, &outlen) {
		return nil, NewOpError("pkey: EVP_PKEY_encrypt", native.PopError())
	}
	return out[:outlen], nil
}

// Decrypt 使用私钥解密数据（须与 Encrypt 输出格式一致）。
//
// 输入密文须由 Encrypt 或等价 OpenSSL 调用生成——SM2 密钥期望 ASN.1 DER（C1C3C2）布局，
// RSA / EC 密钥使用各自 provider 的编码；方法会锁定当前 OS 线程（Tongsuo SM2 provider 对线程敏感），
// 底层 EVP_PKEY_CTX 错误以 OpError 形式包装。
//
// Decrypt decrypts data using the private key. The input ciphertext must
// have been produced by Encrypt (or an equivalent OpenSSL call) because
// the expected encoding is the ASN.1 DER layout with C1C3C2 for SM2 keys
// and the provider-specific encoding for RSA / EC keys.
//
// The method locks the current OS thread because the Tongsuo SM2 provider
// is thread-sensitive. Errors from the underlying EVP_PKEY_CTX are wrapped
// as OpError.
func (k *PKey) Decrypt(data []byte) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx := native.EVP_PKEY_CTX_new_from_pkey(k.handle.Ptr())
	if ctx == nil {
		return nil, NewOpError("pkey: EVP_PKEY_CTX_new_from_pkey", native.PopError())
	}
	defer native.EVP_PKEY_CTX_free(ctx)
	if !native.EVP_PKEY_decrypt_init(ctx) {
		return nil, NewOpError("pkey: EVP_PKEY_decrypt_init", native.PopError())
	}
	var outlen int
	if !native.EVP_PKEY_decrypt(ctx, nil, data, &outlen) {
		return nil, NewOpError("pkey: EVP_PKEY_decrypt(size)", native.PopError())
	}
	out := make([]byte, outlen)
	if !native.EVP_PKEY_decrypt(ctx, out, data, &outlen) {
		return nil, NewOpError("pkey: EVP_PKEY_decrypt", native.PopError())
	}
	return out[:outlen], nil
}

// Sign 使用 SM2withSM3 对 data 签名，返回 ASN.1 DER 签名。
//
// id 为空时使用铜锁默认用户标识（"1234567812345678"，参见 DefaultSM2ID）；
// 内部采用 EVP_DigestSignUpdate + EVP_DigestSignFinal 模式（与官方 Tongsuo C SDK 一致）；
// 方法锁定当前 OS 线程（SM2 provider 对线程敏感）；若底层摘要签名失败，
// 返回的错误以 OpError 形式包装并携带 OpenSSL 错误码。
//
// Sign signs data using SM2withSM3 and returns the signature in ASN.1 DER.
//
// When id is empty the Tongsuo default user identifier
// ("1234567812345678", see DefaultSM2ID) is used. Internally the call
// follows the EVP_DigestSignUpdate + EVP_DigestSignFinal pattern that
// matches the official Tongsuo C SDK. The method locks the current OS
// thread because the SM2 provider is thread-sensitive. If the underlying
// digest sign fails, the returned error is wrapped as OpError carrying
// the OpenSSL error code.
func (k *PKey) Sign(data, id []byte) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mdctx := native.EVP_MD_CTX_new()
	if mdctx == nil {
		return nil, NewOpError("pkey: EVP_MD_CTX_new", native.PopError())
	}
	defer native.EVP_MD_CTX_free(mdctx)
	ok, pctx := native.EVP_DigestSignInit(mdctx, native.EVP_sm3(), nil, k.handle.Ptr())
	if !ok {
		return nil, NewOpError("pkey: EVP_DigestSignInit", native.PopError())
	}
	// id 为空时显式设置 DefaultSM2ID，落实文档契约且不依赖 provider 隐式默认值。
	if len(id) == 0 {
		id = DefaultSM2ID
	}
	if !native.EVP_PKEY_CTX_set1_id(pctx, id) {
		return nil, NewOpError("pkey: EVP_PKEY_CTX_set1_id", native.PopError())
	}
	if !native.EVP_DigestSignUpdate(mdctx, data) {
		return nil, NewOpError("pkey: EVP_DigestSignUpdate", native.PopError())
	}
	siglen := native.EVP_PKEY_size(k.handle.Ptr())
	if siglen <= 0 {
		siglen = 128
	}
	sig := make([]byte, siglen)
	if !native.EVP_DigestSignFinal(mdctx, sig, &siglen) {
		return nil, NewOpError("pkey: EVP_DigestSignFinal", native.PopError())
	}
	return sig[:siglen], nil
}

// Verify 使用 SM2withSM3 验签。
//
// id 为空时使用铜锁默认用户标识（"1234567812345678"，参见 DefaultSM2ID）；
// 方法锁定当前 OS 线程（SM2 provider 对线程敏感）；
// 返回的非 nil 错误始终包装为 OpError 并携带 OpenSSL 错误码，签名非法时亦不例外，
// 调用方需据此区分“签名格式错误”与“验签失败”。
//
// Verify verifies an SM2withSM3 signature.
//
// When id is empty the Tongsuo default user identifier
// ("1234567812345678", see DefaultSM2ID) is used. The method locks the
// current OS thread because the SM2 provider is thread-sensitive. A
// non-nil error is always wrapped as OpError carrying the OpenSSL error
// code, including the case where the signature is invalid (the caller
// must therefore inspect the error to distinguish a malformed signature
// from a verification failure).
func (k *PKey) Verify(data, sig, id []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mdctx := native.EVP_MD_CTX_new()
	if mdctx == nil {
		return NewOpError("pkey: EVP_MD_CTX_new", native.PopError())
	}
	defer native.EVP_MD_CTX_free(mdctx)
	ok, pctx := native.EVP_DigestVerifyInit(mdctx, native.EVP_sm3(), nil, k.handle.Ptr())
	if !ok {
		return NewOpError("pkey: EVP_DigestVerifyInit", native.PopError())
	}
	// id 为空时显式设置 DefaultSM2ID，落实文档契约且不依赖 provider 隐式默认值。
	if len(id) == 0 {
		id = DefaultSM2ID
	}
	if !native.EVP_PKEY_CTX_set1_id(pctx, id) {
		return NewOpError("pkey: EVP_PKEY_CTX_set1_id", native.PopError())
	}
	if !native.EVP_DigestVerifyUpdate(mdctx, data) {
		return NewOpError("pkey: EVP_DigestVerifyUpdate", native.PopError())
	}
	if !native.EVP_DigestVerifyFinal(mdctx, sig) {
		return NewOpError("pkey: EVP_DigestVerifyFinal", native.PopError())
	}
	return nil
}

// Close 释放底层密钥句柄。
//
// 调用是幂等的：对 nil 接收者或已关闭的密钥调用均返回 nil，无额外副作用。
// Close 返回后，同一 *PKey 上的其他方法将返回错误 "pkey: key closed"（查询类方法返回 NidUndef 或 nil），
// 调用方须保证无其他 goroutine 仍在持有该密钥引用。
//
// Close releases the underlying EVP_PKEY handle.
//
// The call is idempotent: invoking it on a nil receiver or on a key that
// has already been closed returns nil without further side effects. After
// Close returns, any other method on the same *PKey returns the error
// "pkey: key closed" (or NidUndef / nil for query-style methods), so the
// caller must guarantee that no concurrent goroutine still holds a
// reference to this key.
func (k *PKey) Close() error {
	if k == nil {
		return nil
	}
	return k.handle.Close()
}

// GenerateRSAKey 生成 RSA 密钥对（bits 为模数位数，如 2048）。
//
// 返回的 *PKey 持有底层 EVP_PKEY，使用完毕须调用 Close 释放；若底层原生调用失败，返回的错误包装 native.PopError 给出的 OpenSSL 错误码。
//
// GenerateRSAKey generates a fresh RSA key pair with the given modulus
// size in bits (commonly 2048 or 4096).
//
// The returned *PKey owns the underlying EVP_PKEY and the caller is
// responsible for calling Close to release it. If the underlying native
// call fails, the returned error wraps the OpenSSL error code from
// native.PopError.
func GenerateRSAKey(bits int) (*PKey, error) {
	p := native.X_EVP_PKEY_Q_keygen_rsa(bits)
	if p == nil {
		return nil, NewOpError("pkey: EVP_PKEY_Q_keygen(RSA)", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// GenerateECKey 生成 EC 密钥对（curve 如 "prime256v1"、"secp384r1"）。
//
// 返回的 *PKey 持有底层 EVP_PKEY，使用完毕须调用 Close 释放；若底层原生调用失败，返回的错误包装 native.PopError 给出的 OpenSSL 错误码。
//
// GenerateECKey generates a fresh EC key pair on the given named curve
// (for example "prime256v1" or "secp384r1").
//
// The returned *PKey owns the underlying EVP_PKEY and the caller is
// responsible for calling Close to release it. If the underlying native
// call fails, the returned error wraps the OpenSSL error code from
// native.PopError.
func GenerateECKey(curve string) (*PKey, error) {
	p := native.X_EVP_PKEY_Q_keygen_ec(curve)
	if p == nil {
		return nil, NewOpError("pkey: EVP_PKEY_Q_keygen(EC)", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// SignDigest 使用指定摘要算法签名。
//
// RSA 默认使用 PKCS#1 v1.5 填充；ECDSA 输出 ASN.1 DER 签名；摘要句柄 md 必须非 nil 且指向有效 Digest（nil 或已关闭的 digest 将返回错误）；
// 若需 RSA-PSS 签名请改用 SignDigestPSS。方法锁定当前 OS 线程（SM2 provider 对线程敏感）。
//
// SignDigest signs data using the supplied digest algorithm.
//
// RSA keys default to PKCS#1 v1.5 padding; ECDSA keys emit the signature
// in ASN.1 DER. The digest handle md must be non-nil and point at a live
// Digest (a nil or closed digest returns an error). For RSA-PSS signatures
// use SignDigestPSS instead. The method locks the current OS thread
// because the SM2 provider is thread-sensitive.
func (k *PKey) SignDigest(data []byte, md *Digest) ([]byte, error) {
	return k.signDigest(data, md, nil)
}

// SignDigestPSS 使用 RSA-PSS 签名。
//
// saltLen 可为正整数或 native.RsaPssSaltLen* 哨兵常量（例如 native.RsaPssSaltLenDigest 表示盐长度等于摘要长度）；
// 传入的摘要 md 同时用作 MGF1 哈希；本方法仅适用于 RSA 密钥，其他类型密钥会从底层 EVP_PKEY_CTX 返回错误。
//
// SignDigestPSS signs data with RSA-PSS.
//
// saltLen selects the PSS salt length and may be a positive integer or one
// of the native.RsaPssSaltLen* sentinel constants (for example
// native.RsaPssSaltLenDigest, which sets the salt length equal to the
// digest length). The supplied digest md is also used as the MGF1 hash.
// The method only applies to RSA keys; other key types return an error
// from the underlying EVP_PKEY_CTX.
func (k *PKey) SignDigestPSS(data []byte, md *Digest, saltLen int) ([]byte, error) {
	return k.signDigest(data, md, func(pctx unsafe.Pointer) error {
		if !native.EVP_PKEY_CTX_set_rsa_padding(pctx, native.RsaPaddingPSS) {
			return NewOpError("pkey: EVP_PKEY_CTX_set_rsa_padding(PSS)", native.PopError())
		}
		if !native.EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltLen) {
			return NewOpError("pkey: EVP_PKEY_CTX_set_rsa_pss_saltlen", native.PopError())
		}
		if !native.EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md.handle.Ptr()) {
			return NewOpError("pkey: EVP_PKEY_CTX_set_rsa_mgf1_md", native.PopError())
		}
		return nil
	})
}

// signDigest 通用签名实现（EVP_DigestSign*）。
//
// signDigest is the generic signing implementation backed by the
// OpenSSL EVP_DigestSign* family. setOpts may apply algorithm-specific
// padding (e.g. PSS) before signing; it is invoked under the OS thread
// lock taken by signDigest.
func (k *PKey) signDigest(data []byte, md *Digest, setOpts func(unsafe.Pointer) error) ([]byte, error) {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return nil, fmt.Errorf("pkey: key closed")
	}
	if md == nil || md.handle == nil {
		return nil, fmt.Errorf("pkey: invalid digest")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mdctx := native.EVP_MD_CTX_new()
	if mdctx == nil {
		return nil, NewOpError("pkey: EVP_MD_CTX_new", native.PopError())
	}
	defer native.EVP_MD_CTX_free(mdctx)
	ok, pctx := native.EVP_DigestSignInit(mdctx, md.handle.Ptr(), nil, k.handle.Ptr())
	if !ok {
		return nil, NewOpError("pkey: EVP_DigestSignInit", native.PopError())
	}
	if setOpts != nil {
		if err := setOpts(pctx); err != nil {
			return nil, err
		}
	}
	if !native.EVP_DigestSignUpdate(mdctx, data) {
		return nil, NewOpError("pkey: EVP_DigestSignUpdate", native.PopError())
	}
	siglen := native.EVP_PKEY_size(k.handle.Ptr())
	if siglen <= 0 {
		return nil, fmt.Errorf("pkey: EVP_PKEY_size failed")
	}
	sig := make([]byte, siglen)
	if !native.EVP_DigestSignFinal(mdctx, sig, &siglen) {
		return nil, NewOpError("pkey: EVP_DigestSignFinal", native.PopError())
	}
	return sig[:siglen], nil
}

// VerifyDigest 使用指定摘要算法验签（RSA PKCS#1 v1.5 / ECDSA DER）。
//
// RSA 密钥假设使用 PKCS#1 v1.5 填充；ECDSA 密钥期望 ASN.1 DER 签名；摘要句柄 md 必须非 nil 且指向有效 Digest（nil 或已关闭的 digest 将返回错误）；
// 若需 RSA-PSS 验签请改用 VerifyDigestPSS。方法锁定当前 OS 线程（SM2 provider 对线程敏感）。
//
// VerifyDigest verifies a signature using the supplied digest algorithm.
//
// RSA keys assume PKCS#1 v1.5 padding; ECDSA keys expect the signature
// in ASN.1 DER. The digest handle md must be non-nil and point at a live
// Digest (a nil or closed digest returns an error). For RSA-PSS
// verification use VerifyDigestPSS instead. The method locks the
// current OS thread because the SM2 provider is thread-sensitive.
func (k *PKey) VerifyDigest(data, sig []byte, md *Digest) error {
	return k.verifyDigest(data, sig, md, nil)
}

// VerifyDigestPSS 使用 RSA-PSS 验签。
//
// saltLen 可为正整数或 native.RsaPssSaltLen* 哨兵常量（例如 native.RsaPssSaltLenDigest）；
// 传入的摘要 md 同时用作 MGF1 哈希；本方法仅适用于 RSA 密钥，其他类型密钥将从底层 EVP_PKEY_CTX 返回错误。
//
// VerifyDigestPSS verifies an RSA-PSS signature.
//
// saltLen selects the PSS salt length and may be a positive integer or
// one of the native.RsaPssSaltLen* sentinel constants (for example
// native.RsaPssSaltLenDigest). The supplied digest md is also used as
// the MGF1 hash. The method only applies to RSA keys; other key types
// return an error from the underlying EVP_PKEY_CTX.
func (k *PKey) VerifyDigestPSS(data, sig []byte, md *Digest, saltLen int) error {
	return k.verifyDigest(data, sig, md, func(pctx unsafe.Pointer) error {
		if !native.EVP_PKEY_CTX_set_rsa_padding(pctx, native.RsaPaddingPSS) {
			return NewOpError("pkey: EVP_PKEY_CTX_set_rsa_padding(PSS)", native.PopError())
		}
		if !native.EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltLen) {
			return NewOpError("pkey: EVP_PKEY_CTX_set_rsa_pss_saltlen", native.PopError())
		}
		if !native.EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md.handle.Ptr()) {
			return NewOpError("pkey: EVP_PKEY_CTX_set_rsa_mgf1_md", native.PopError())
		}
		return nil
	})
}

// verifyDigest 通用验签实现（EVP_DigestVerify*）。
//
// verifyDigest is the generic signature-verification implementation
// backed by the OpenSSL EVP_DigestVerify* family. setOpts may apply
// algorithm-specific padding (e.g. PSS) before verification; it is
// invoked under the OS thread lock taken by verifyDigest.
func (k *PKey) verifyDigest(data, sig []byte, md *Digest, setOpts func(unsafe.Pointer) error) error {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return fmt.Errorf("pkey: key closed")
	}
	if md == nil || md.handle == nil {
		return fmt.Errorf("pkey: invalid digest")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mdctx := native.EVP_MD_CTX_new()
	if mdctx == nil {
		return NewOpError("pkey: EVP_MD_CTX_new", native.PopError())
	}
	defer native.EVP_MD_CTX_free(mdctx)
	ok, pctx := native.EVP_DigestVerifyInit(mdctx, md.handle.Ptr(), nil, k.handle.Ptr())
	if !ok {
		return NewOpError("pkey: EVP_DigestVerifyInit", native.PopError())
	}
	if setOpts != nil {
		if err := setOpts(pctx); err != nil {
			return err
		}
	}
	if !native.EVP_DigestVerifyUpdate(mdctx, data) {
		return NewOpError("pkey: EVP_DigestVerifyUpdate", native.PopError())
	}
	if !native.EVP_DigestVerifyFinal(mdctx, sig) {
		return NewOpError("pkey: EVP_DigestVerifyFinal", native.PopError())
	}
	return nil
}

// EncryptPKCS1v15 使用 RSA PKCS#1 v1.5 填充加密。
//
// 该方法是对 Encrypt 的薄包装，因此同样要求非空明文与 RSA 公钥；非 RSA 密钥将从底层 EVP_PKEY_CTX 返回错误；失败时返回包装的 OpError。
// EncryptPKCS1v15 encrypts data with RSA PKCS#1 v1.5 padding.
//
// This is a thin wrapper around Encrypt and therefore requires an RSA
// public key; non-RSA keys return an error from the underlying
// EVP_PKEY_CTX. Empty plaintext is accepted (matching the Go stdlib
// rsa.EncryptPKCS1v15). Returns the wrapped OpError on failure.
func (k *PKey) EncryptPKCS1v15(data []byte) ([]byte, error) {
	return k.Encrypt(data)
}

// DecryptPKCS1v15 使用 RSA PKCS#1 v1.5 填充解密。
//
// 该方法是对 Decrypt 的薄包装，因此要求 RSA 私钥；非 RSA 密钥将从底层 EVP_PKEY_CTX 返回错误；失败时返回包装的 OpError。
//
// DecryptPKCS1v15 decrypts data with RSA PKCS#1 v1.5 padding.
//
// This is a thin wrapper around Decrypt and therefore requires an RSA
// private key; non-RSA keys return an error from the underlying
// EVP_PKEY_CTX. Returns the wrapped OpError on failure.
func (k *PKey) DecryptPKCS1v15(data []byte) ([]byte, error) {
	return k.Decrypt(data)
}

// EncryptOAEP 使用 RSA-OAEP 填充加密。md 指定 OAEP/MGF1 摘要（如 SHA256）。
//
// 摘要 md 同时用于 OAEP 编码（EVP_PKEY_CTX_set_rsa_oaep_md）与 MGF1 掩码生成（EVP_PKEY_CTX_set_rsa_mgf1_md）；
// 传入 md = nil 时使用 OpenSSL 默认的 SHA-1。密钥必须为 RSA 公钥；空明文允许（与
// Go 标准库 rsa.EncryptOAEP 一致）；失败时返回包装的 OpError。
//
// EncryptOAEP encrypts data with RSA-OAEP padding.
//
// The digest md is used for both the OAEP encoding (EVP_PKEY_CTX_set_rsa_oaep_md)
// and the MGF1 mask-generation function (EVP_PKEY_CTX_set_rsa_mgf1_md);
// pass md = nil to let OpenSSL use its default SHA-1. The key must be an
// RSA public key. Empty plaintext is accepted (matching the Go stdlib
// rsa.EncryptOAEP). Returns the wrapped OpError on failure.
func (k *PKey) EncryptOAEP(data []byte, md *Digest) ([]byte, error) {
	return k.encryptWithOpts(data, func(ctx unsafe.Pointer) error {
		if !native.EVP_PKEY_CTX_set_rsa_padding(ctx, native.RsaPaddingOAEP) {
			return NewOpError("pkey: EVP_PKEY_CTX_set_rsa_padding(OAEP)", native.PopError())
		}
		if md != nil && md.handle != nil {
			if !native.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md.handle.Ptr()) {
				return NewOpError("pkey: EVP_PKEY_CTX_set_rsa_oaep_md", native.PopError())
			}
			if !native.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md.handle.Ptr()) {
				return NewOpError("pkey: EVP_PKEY_CTX_set_rsa_mgf1_md", native.PopError())
			}
		}
		return nil
	})
}

// DecryptOAEP 使用 RSA-OAEP 填充解密。
//
// 摘要 md 同时用于 OAEP 编码与 MGF1 掩码生成；传入 md = nil 时使用 OpenSSL 默认的 SHA-1。
// 密钥必须为 RSA 私钥，其他类型密钥将从底层 EVP_PKEY_CTX 返回错误；失败时返回包装的 OpError。
//
// DecryptOAEP decrypts data with RSA-OAEP padding.
//
// The digest md is used for both the OAEP encoding and the MGF1 mask
// generation; pass md = nil to let OpenSSL use its default SHA-1. The
// key must be an RSA private key; other key types return an error from
// the underlying EVP_PKEY_CTX. Returns the wrapped OpError on failure.
func (k *PKey) DecryptOAEP(data []byte, md *Digest) ([]byte, error) {
	return k.decryptWithOpts(data, func(ctx unsafe.Pointer) error {
		if !native.EVP_PKEY_CTX_set_rsa_padding(ctx, native.RsaPaddingOAEP) {
			return NewOpError("pkey: EVP_PKEY_CTX_set_rsa_padding(OAEP)", native.PopError())
		}
		if md != nil && md.handle != nil {
			if !native.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md.handle.Ptr()) {
				return NewOpError("pkey: EVP_PKEY_CTX_set_rsa_oaep_md", native.PopError())
			}
			if !native.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md.handle.Ptr()) {
				return NewOpError("pkey: EVP_PKEY_CTX_set_rsa_mgf1_md", native.PopError())
			}
		}
		return nil
	})
}

// encryptWithOpts 带选项的 EVP_PKEY_encrypt 封装。
//
// encryptWithOpts wraps EVP_PKEY_encrypt, allowing the caller to apply
// algorithm-specific options (e.g. padding) via setOpts. Empty plaintext
// policy is left to the algorithm wrapper (RSA PKCS#1 v1.5 / OAEP accept
// it, matching stdlib).
func (k *PKey) encryptWithOpts(data []byte, setOpts func(unsafe.Pointer) error) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx := native.EVP_PKEY_CTX_new_from_pkey(k.handle.Ptr())
	if ctx == nil {
		return nil, NewOpError("pkey: EVP_PKEY_CTX_new_from_pkey", native.PopError())
	}
	defer native.EVP_PKEY_CTX_free(ctx)
	if !native.EVP_PKEY_encrypt_init(ctx) {
		return nil, NewOpError("pkey: EVP_PKEY_encrypt_init", native.PopError())
	}
	if setOpts != nil {
		if err := setOpts(ctx); err != nil {
			return nil, err
		}
	}
	var outlen int
	if !native.EVP_PKEY_encrypt(ctx, nil, data, &outlen) {
		return nil, NewOpError("pkey: EVP_PKEY_encrypt(size)", native.PopError())
	}
	out := make([]byte, outlen)
	if !native.EVP_PKEY_encrypt(ctx, out, data, &outlen) {
		return nil, NewOpError("pkey: EVP_PKEY_encrypt", native.PopError())
	}
	return out[:outlen], nil
}

// decryptWithOpts 带选项的 EVP_PKEY_decrypt 封装。
//
// decryptWithOpts wraps EVP_PKEY_decrypt, allowing the caller to apply
// algorithm-specific options (e.g. padding) via setOpts.
func (k *PKey) decryptWithOpts(data []byte, setOpts func(unsafe.Pointer) error) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx := native.EVP_PKEY_CTX_new_from_pkey(k.handle.Ptr())
	if ctx == nil {
		return nil, NewOpError("pkey: EVP_PKEY_CTX_new_from_pkey", native.PopError())
	}
	defer native.EVP_PKEY_CTX_free(ctx)
	if !native.EVP_PKEY_decrypt_init(ctx) {
		return nil, NewOpError("pkey: EVP_PKEY_decrypt_init", native.PopError())
	}
	if setOpts != nil {
		if err := setOpts(ctx); err != nil {
			return nil, err
		}
	}
	var outlen int
	if !native.EVP_PKEY_decrypt(ctx, nil, data, &outlen) {
		return nil, NewOpError("pkey: EVP_PKEY_decrypt(size)", native.PopError())
	}
	out := make([]byte, outlen)
	if !native.EVP_PKEY_decrypt(ctx, out, data, &outlen) {
		return nil, NewOpError("pkey: EVP_PKEY_decrypt", native.PopError())
	}
	return out[:outlen], nil
}

// KeyParams 表示密钥参数（仅对应类型字段被填充）。
//
// 仅填充与底层密钥类型匹配的字段：Type 始终被赋值；RSA 密钥填充 N/E/D/P/Q；EC / SM2 密钥填充 Curve/D/X/Y。
// 提取逻辑与底层 provider 参数名（如 "n"、"e"、"priv"、"rsa-factor1"、"rsa-factor2"、"group"、"pub"）请参见 PKey.Params。
//
// KeyParams holds the algorithm-specific parameters extracted from a key.
//
// Only the fields that apply to the underlying key type are populated:
// Type is always set; RSA keys populate N/E/D/P/Q; EC and SM2 keys
// populate Curve/D/X/Y. See PKey.Params for the extraction logic and the
// underlying provider parameter names (for example "n", "e", "priv",
// "rsa-factor1", "rsa-factor2", "group", and "pub").
type KeyParams struct {
	Type string // "RSA" / "EC" / "SM2"

	N *big.Int // RSA 模数
	E *big.Int // RSA 公钥指数
	D *big.Int // RSA 私钥指数 / EC 私钥标量
	P *big.Int // RSA 质数 p
	Q *big.Int // RSA 质数 q

	Curve string   // EC 曲线名（如 "prime256v1"）
	X     *big.Int // EC 公钥点 X
	Y     *big.Int // EC 公钥点 Y
}

// bnParam 读取 PKEY 的 BIGNUM 参数（如 RSA n/e/d 或 EC 曲线系数）。
//
// bnParam fetches a BIGNUM-typed OpenSSL parameter from k by name and
// returns it as a *big.Int. It returns nil when the parameter is
// missing or the underlying call fails; the caller must treat a nil
// result as "absent".
func bnParam(k *PKey, name string) *big.Int {
	b, ok := native.EVP_PKEY_get_bn_param(k.handle.Ptr(), name)
	if !ok {
		return nil
	}
	return new(big.Int).SetBytes(b)
}

// Params 返回密钥参数。
//
// 方法在 nil 接收者或已关闭的密钥上调用时返回 nil；RSA 密钥通过 EVP_PKEY_get_bn_param 读取
// provider 参数 "n"、"e"、"d"、"rsa-factor1"、"rsa-factor2"；EC / SM2 密钥使用 "group"、"priv"、"pub"
// 参数以恢复曲线名、私钥标量与仿射公钥坐标；填充字段请参见 KeyParams。
//
// Params returns the algorithm-specific parameters of the key.
//
// The method returns nil when called on a nil receiver or on a key that
// has already been closed. For RSA keys the provider parameter names
// "n", "e", "d", "rsa-factor1" and "rsa-factor2" are read via
// EVP_PKEY_get_bn_param; for EC / SM2 keys the "group", "priv" and "pub"
// parameters are used to recover the curve name, the private scalar and
// the affine public coordinates. See KeyParams for the populated fields.
func (k *PKey) Params() *KeyParams {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return nil
	}
	p := &KeyParams{Type: k.Algorithm()}
	if p.Type == "RSA" {
		p.N = bnParam(k, "n")
		p.E = bnParam(k, "e")
		p.D = bnParam(k, "d")
		// provider 暴露的质数因子参数名为 rsa-factor1/rsa-factor2。
		p.P = bnParam(k, "rsa-factor1")
		p.Q = bnParam(k, "rsa-factor2")
		return p
	}
	// EC / SM2：私钥标量参数名为 "priv"（OSSL_PKEY_PARAM_EC_PRIV_KEY）。
	if curve, ok := native.EVP_PKEY_get_utf8_string_param(k.handle.Ptr(), "group"); ok {
		p.Curve = curve
	}
	p.D = bnParam(k, "priv")
	if pub, ok := native.EVP_PKEY_get_octet_string_param(k.handle.Ptr(), "pub"); ok && len(pub) > 0 && pub[0] == 0x04 {
		coord := (len(pub) - 1) / 2
		if coord > 0 && len(pub)-1 == 2*coord {
			p.X = new(big.Int).SetBytes(pub[1 : 1+coord])
			p.Y = new(big.Int).SetBytes(pub[1+coord:])
		}
	}
	return p
}

// MarshalEncryptedPEM 用口令加密导出私钥为 PEM（AES-256-CBC，PKCS#8）。
//
// 加密算法为 OpenSSL 默认的 AES-256-CBC + PBKDF2 派生密钥；若密钥已通过 Close 释放，或底层 OpenSSL 写失败，
// 均返回包装为 OpError 的错误。
//
// MarshalEncryptedPEM serializes the private key to an encrypted PKCS#8
// PEM block ("-----BEGIN ENCRYPTED PRIVATE KEY-----") using the given
// password.
//
// The encryption algorithm is the OpenSSL default of AES-256-CBC with
// PBKDF2-derived keys. Returns an error if the key has been closed via
// Close, or if the underlying OpenSSL write fails (errors are wrapped as
// OpError).
func (k *PKey) MarshalEncryptedPEM(pass string) ([]byte, error) {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return nil, fmt.Errorf("pkey: key closed")
	}
	bio := native.BIO_new(native.BIO_s_mem())
	if bio == nil {
		return nil, NewOpError("pkey: BIO_new", native.PopError())
	}
	defer native.BIO_free(bio)
	if !native.X_PEM_write_bio_PrivateKey_enc(bio, k.handle.Ptr(), pass) {
		return nil, NewOpError("pkey: PEM_write_bio_PrivateKey(enc)", native.PopError())
	}
	return readAllBIO(bio)
}

// LoadPrivateKeyPEMEncrypted 从加密 PEM 加载私钥。
//
// pass 必须与加密时使用的口令一致；口令错误会以包装的 OpError 形式返回，
// 其中包含 native.PopError 给出的 OpenSSL 错误码；返回的 *PKey 持有底层 EVP_PKEY，使用完毕须调用 Close 释放。
//
// LoadPrivateKeyPEMEncrypted loads a private key from an encrypted
// PEM block ("-----BEGIN ENCRYPTED PRIVATE KEY-----").
//
// The pass argument must match the password that was used during
// encryption; an incorrect password surfaces as a wrapped OpError
// containing the OpenSSL error code from native.PopError. The returned
// *PKey owns the underlying EVP_PKEY and the caller must invoke Close
// to release it.
func LoadPrivateKeyPEMEncrypted(pemBytes []byte, pass string) (*PKey, error) {
	bio := native.BIO_new_mem_buf(pemBytes)
	if bio == nil {
		return nil, NewOpError("pkey: BIO_new_mem_buf", native.PopError())
	}
	defer native.BIO_free(bio)
	p := native.X_PEM_read_bio_PrivateKey_pass(bio, pass)
	if p == nil {
		return nil, NewOpError("pkey: PEM_read_bio_PrivateKey(enc)", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// ChangePrivateKeyPassword 读取旧口令加密的 PEM 私钥并导出为新口令加密。
//
// 内部使用 LoadPrivateKeyPEMEncrypted + oldPass 加载密钥，再以 MarshalEncryptedPEM + newPass 重新导出；
// 加载或导出步骤中的错误原样向上传递（来自 native 层时包装为 OpError）；中间 PKey 在函数返回前已释放。
//
// ChangePrivateKeyPassword reads a private key from an old-password
// encrypted PEM block and returns a new-password encrypted PEM block.
//
// Internally the function loads the key with LoadPrivateKeyPEMEncrypted
// using oldPass and then exports it with MarshalEncryptedPEM using
// newPass. Any error from the load or export step is propagated to the
// caller verbatim (wrapped as OpError when it originates in the native
// layer). The intermediate PKey is released before the function returns.
func ChangePrivateKeyPassword(pemBytes []byte, oldPass, newPass string) ([]byte, error) {
	k, err := LoadPrivateKeyPEMEncrypted(pemBytes, oldPass)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.MarshalEncryptedPEM(newPass)
}

// MarshalPrivateKeyPKCS1PEM 导出 RSA 私钥为 PKCS#1 PEM（"BEGIN RSA PRIVATE KEY"）。
//
// 本方法仅适用于 RSA 密钥；任意密钥（含 SM2）请改用 MarshalPrivateKeyPEM（PKCS#8）；
// 若密钥已通过 Close 释放，或底层 OpenSSL i2d_PrivateKey 调用失败，均返回包装为 OpError 的错误。
//
// MarshalPrivateKeyPKCS1PEM serializes an RSA private key to the legacy
// PKCS#1 PEM format ("-----BEGIN RSA PRIVATE KEY-----").
//
// This method only applies to RSA keys; for arbitrary keys (including
// SM2) use MarshalPrivateKeyPEM (PKCS#8) instead. Returns an error if
// the key has been closed via Close, or if the underlying OpenSSL
// i2d_PrivateKey call fails (wrapped as OpError).
func (k *PKey) MarshalPrivateKeyPKCS1PEM() ([]byte, error) {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return nil, fmt.Errorf("pkey: key closed")
	}
	der, ok := native.I2d_PrivateKey(k.handle.Ptr())
	if !ok {
		return nil, NewOpError("pkey: i2d_PrivateKey", native.PopError())
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), nil
}

// LoadPrivateKeyPKCS1PEM 从 PKCS#1 PEM 加载 RSA 私钥。
//
// pemBytes 不包含有效 PEM 块，或底层 d2i_PrivateKey 调用失败时返回错误（包装为 OpError）；
// 返回的 *PKey 持有底层 EVP_PKEY，使用完毕须调用 Close 释放。
//
// LoadPrivateKeyPKCS1PEM loads an RSA private key from a legacy PKCS#1
// PEM block ("-----BEGIN RSA PRIVATE KEY-----").
//
// The function returns an error when pemBytes does not contain a valid
// PEM block, or when the underlying d2i_PrivateKey call fails (wrapped
// as OpError). The returned *PKey owns the underlying EVP_PKEY and the
// caller must invoke Close to release it.
func LoadPrivateKeyPKCS1PEM(pemBytes []byte) (*PKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("pkey: invalid PKCS#1 PEM")
	}
	p := native.D2i_PrivateKey(block.Bytes)
	if p == nil {
		return nil, NewOpError("pkey: d2i_PrivateKey", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// Equal 判断两个密钥是否等价（含私钥参数）。
//
// 任一接收者为 nil、handle 为 nil 或已关闭时返回 false；比较委托给 OpenSSL 的 EVP_PKEY_eq，
// 因此在底层密钥类型支持时为常数时间（RSA / EC / Ed25519 等）。
//
// Equal reports whether two keys are equivalent, including their private
// parameters when applicable.
//
// It returns false when either side is nil, whose handle is nil, or whose
// handle has been closed. Comparison is delegated to OpenSSL's
// EVP_PKEY_eq and is therefore constant-time when the underlying key
// type supports it (RSA, EC, Ed25519, ...).
func (k *PKey) Equal(other *PKey) bool {
	if k == nil || other == nil || k.handle == nil || other.handle == nil {
		return false
	}
	return native.EVP_PKEY_eq(k.handle.Ptr(), other.handle.Ptr()) == 1
}

// PublicEqual 判断两个密钥的公钥部分是否一致（比较 SubjectPublicKeyInfo DER）。
//
// 任一接收者为 nil、handle 为 nil、已关闭，或底层 i2d_PUBKEY 调用失败时返回 false；
// 比较忽略私钥参数，因此私钥与其内嵌的公钥相互匹配。
//
// PublicEqual reports whether the public part of two keys is the same,
// by comparing their SubjectPublicKeyInfo (SPKI) DER encodings.
//
// It returns false when either side is nil, whose handle is nil, whose
// handle has been closed, or when the underlying i2d_PUBKEY call fails.
// The comparison ignores private parameters, so a private key matches
// its embedded public key (and vice versa).
func (k *PKey) PublicEqual(other *PKey) bool {
	if k == nil || other == nil || k.handle == nil || other.handle == nil {
		return false
	}
	a, ok1 := native.I2d_PUBKEY(k.handle.Ptr())
	b, ok2 := native.I2d_PUBKEY(other.handle.Ptr())
	if !ok1 || !ok2 {
		return false
	}
	return bytes.Equal(a, b)
}

// digestForSigner 按签名密钥类型选择摘要：SM2→SM3，RSA/ECDSA→SHA256。
//
// digestForSigner picks the default digest for sign operations:
// SM2 keys use SM3 (per GB/T 32918), RSA and ECDSA keys use SHA-256.
// Other key types fall back to SHA-256.
func digestForSigner(k *PKey) *Digest {
	if k != nil && k.TypeID() == native.EvpPkeySM2 {
		return SM3()
	}
	switch k.BaseID() {
	case native.EvpPkeyRSA, native.EvpPkeyEC:
		return SHA256()
	default:
		return SM3()
	}
}
