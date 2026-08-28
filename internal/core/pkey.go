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

// GenerateRSAKey 生成 RSA 密钥对（bits 为模数位数，如 2048）。
func GenerateRSAKey(bits int) (*PKey, error) {
	p := native.X_EVP_PKEY_Q_keygen_rsa(bits)
	if p == nil {
		return nil, NewOpError("pkey: EVP_PKEY_Q_keygen(RSA)", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// GenerateECKey 生成 EC 密钥对（curve 如 "prime256v1"、"secp384r1"）。
func GenerateECKey(curve string) (*PKey, error) {
	p := native.X_EVP_PKEY_Q_keygen_ec(curve)
	if p == nil {
		return nil, NewOpError("pkey: EVP_PKEY_Q_keygen(EC)", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// SignDigest 使用指定摘要算法签名。
// RSA 默认 PKCS#1 v1.5 填充；ECDSA 输出 ASN.1 DER 签名。
func (k *PKey) SignDigest(data []byte, md *Digest) ([]byte, error) {
	return k.signDigest(data, md, nil)
}

// SignDigestPSS 使用 RSA-PSS 签名。saltLen 取 native.RsaPssSaltLenDigest 等常量。
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
func (k *PKey) VerifyDigest(data, sig []byte, md *Digest) error {
	return k.verifyDigest(data, sig, md, nil)
}

// VerifyDigestPSS 使用 RSA-PSS 验签。
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
func (k *PKey) EncryptPKCS1v15(data []byte) ([]byte, error) {
	return k.Encrypt(data)
}

// DecryptPKCS1v15 使用 RSA PKCS#1 v1.5 填充解密。
func (k *PKey) DecryptPKCS1v15(data []byte) ([]byte, error) {
	return k.Decrypt(data)
}

// EncryptOAEP 使用 RSA-OAEP 填充加密。md 指定 OAEP/MGF1 摘要（如 SHA256）。
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
func (k *PKey) encryptWithOpts(data []byte, setOpts func(unsafe.Pointer) error) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pkey: encryption requires non-empty plaintext")
	}
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

func bnParam(k *PKey, name string) *big.Int {
	b, ok := native.EVP_PKEY_get_bn_param(k.handle.Ptr(), name)
	if !ok {
		return nil
	}
	return new(big.Int).SetBytes(b)
}

// Params 返回密钥参数。
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
func ChangePrivateKeyPassword(pemBytes []byte, oldPass, newPass string) ([]byte, error) {
	k, err := LoadPrivateKeyPEMEncrypted(pemBytes, oldPass)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.MarshalEncryptedPEM(newPass)
}

// MarshalPrivateKeyPKCS1PEM 导出 RSA 私钥为 PKCS#1 PEM（"BEGIN RSA PRIVATE KEY"）。
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
func (k *PKey) Equal(other *PKey) bool {
	if k == nil || other == nil || k.handle == nil || other.handle == nil {
		return false
	}
	return native.EVP_PKEY_eq(k.handle.Ptr(), other.handle.Ptr()) == 1
}

// PublicEqual 判断两个密钥的公钥部分是否一致（比较 SubjectPublicKeyInfo DER）。
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
