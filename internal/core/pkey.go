package core

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// DefaultSM2ID 为 SM2 算法默认用户标识（GM/T 0003-2012）。
var DefaultSM2ID = []byte("1234567812345678")

// PKey 表示一个非对称密钥对象（EVP_PKEY 的包装）。
// 当前用于 SM2；后续阶段可扩展 RSA / EC 等。
type PKey struct {
	handle *Handle
}

// BaseID 返回密钥底层类型 ID（如 native.EvpPkeyEC）。
func (k *PKey) BaseID() int {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return native.NidUndef
	}
	return native.EVP_PKEY_get_base_id(k.handle.Ptr())
}

// TypeID 返回密钥完整类型 ID（如 SM2 密钥返回 native.EvpPkeySM2）。
func (k *PKey) TypeID() int {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return native.NidUndef
	}
	return native.EVP_PKEY_get_id(k.handle.Ptr())
}

// Algorithm 返回密钥算法名（如 "SM2"、"RSA"、"EC"）；未知返回 "id:<n>"。
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
func GenerateSM2Key() (*PKey, error) {
	p := native.X_EVP_PKEY_Q_keygen_sm2()
	if p == nil {
		return nil, NewOpError("pkey: EVP_PKEY_Q_keygen(SM2)", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// LoadPrivateKeyPEM 从 PEM（PKCS#8）加载密钥（私钥）。
func LoadPrivateKeyPEM(pem []byte) (*PKey, error) {
	return loadPEM("pkey: PEM_read_bio_PrivateKey", native.X_PEM_read_bio_PrivateKey, pem)
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载密钥（公钥）。
func LoadPublicKeyPEM(pem []byte) (*PKey, error) {
	return loadPEM("pkey: PEM_read_bio_PUBKEY", native.X_PEM_read_bio_PUBKEY, pem)
}

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
func (k *PKey) MarshalPrivateKeyPEM() ([]byte, error) {
	return k.marshalPEM("pkey: PEM_write_bio_PrivateKey", native.X_PEM_write_bio_PrivateKey)
}

// MarshalPublicKeyPEM 将公钥导出为 PEM（SubjectPublicKeyInfo）。
func (k *PKey) MarshalPublicKeyPEM() ([]byte, error) {
	return k.marshalPEM("pkey: PEM_write_bio_PUBKEY", native.X_PEM_write_bio_PUBKEY)
}

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
// 注意：Tongsuo 8.x（OpenSSL 3.x）SM2 加密输出为 ASN.1 DER 编码
// （内含 C1C3C2），与 openssl pkeyutl 输出一致。
// SM2 不支持空明文，data 必须非空。
func (k *PKey) Encrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pkey: SM2 encryption requires non-empty plaintext")
	}
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
// id 为空时使用铜锁默认用户标识（"1234567812345678"）。
// 采用 EVP_DigestSignUpdate + EVP_DigestSignFinal 模式（官方 SDK 同款）。
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
	if len(id) > 0 && !native.EVP_PKEY_CTX_set1_id(pctx, id) {
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

// Verify 使用 SM2withSM3 验签。id 为空时使用铜锁默认用户标识。
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
	if len(id) > 0 && !native.EVP_PKEY_CTX_set1_id(pctx, id) {
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

// Close 释放底层密钥句柄。幂等。
func (k *PKey) Close() error {
	if k == nil {
		return nil
	}
	return k.handle.Close()
}
