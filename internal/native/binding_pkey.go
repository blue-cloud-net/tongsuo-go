package native

/*
#include <openssl/evp.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// X_EVP_PKEY_Q_keygen_sm2 生成 SM2 密钥对（经 shim 包装可变参函数）。
// X_EVP_PKEY_Q_keygen_sm2 (shim) generates an SM2 key pair via EVP_PKEY_Q_keygen.
// The caller owns the returned EVP_PKEY and must release it with EVP_PKEY_free.
func X_EVP_PKEY_Q_keygen_sm2() unsafe.Pointer {
	return unsafe.Pointer(C.X_EVP_PKEY_Q_keygen_sm2())
}

// X_PEM_read_bio_PrivateKey 从 BIO 读取 PEM 私钥（PKCS#8）。
// X_PEM_read_bio_PrivateKey (shim) reads a PKCS#8 PEM-encoded private key
// from bio. Returns NULL on failure; otherwise the caller owns the EVP_PKEY
// and must release it with EVP_PKEY_free.
func X_PEM_read_bio_PrivateKey(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_PrivateKey((*C.BIO)(bio)))
}

// X_PEM_write_bio_PrivateKey 将私钥以 PEM（PKCS#8）写入 BIO。
// X_PEM_write_bio_PrivateKey (shim) writes pkey to bio as unencrypted
// PKCS#8 PEM. Returns true on success.
func X_PEM_write_bio_PrivateKey(bio unsafe.Pointer, pkey unsafe.Pointer) bool {
	return C.X_PEM_write_bio_PrivateKey((*C.BIO)(bio), (*C.EVP_PKEY)(pkey)) == 1
}

// X_PEM_read_bio_PUBKEY 从 BIO 读取 PEM 公钥（SubjectPublicKeyInfo）。
// X_PEM_read_bio_PUBKEY (shim) reads a SubjectPublicKeyInfo PEM-encoded
// public key from bio. Returns NULL on failure; the caller owns the EVP_PKEY.
func X_PEM_read_bio_PUBKEY(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_PUBKEY((*C.BIO)(bio)))
}

// X_PEM_write_bio_PUBKEY 将公钥以 PEM（SubjectPublicKeyInfo）写入 BIO。
// X_PEM_write_bio_PUBKEY (shim) writes pkey to bio as SubjectPublicKeyInfo
// PEM. Returns true on success.
func X_PEM_write_bio_PUBKEY(bio unsafe.Pointer, pkey unsafe.Pointer) bool {
	return C.X_PEM_write_bio_PUBKEY((*C.BIO)(bio), (*C.EVP_PKEY)(pkey)) == 1
}

// EVP_PKEY_free 释放密钥对象。
// EVP_PKEY_free releases pkey. Safe on NULL; the pointer must not be used
// after free.
func EVP_PKEY_free(pkey unsafe.Pointer) {
	C.EVP_PKEY_free((*C.EVP_PKEY)(pkey))
}

// EVP_PKEY 类型常量（来自 evp.h 宏，OpenSSL 3.x / 铜锁）。
//
// EvpPkeyRSA, EvpPkeyDSA, EvpPkeyEC, EvpPkeyED25519, EvpPkeyED448,
// EvpPkeyX25519 and EvpPkeySM2 are the EVP_PKEY base IDs returned by
// EVP_PKEY_get_base_id; use EvpPkeySM2 to detect SM2 keys (which otherwise
// report as EvpPkeyEC via get_base_id but EvpPkeySM2 via get_id). The EdDSA
// and X25519 IDs also come from obj_mac.h (Tongsuo/OpenSSL 3.x) and match
// the numeric values exposed via OBJ_txt2nid.
const (
	EvpPkeyRSA    = 6
	EvpPkeyDSA    = 116
	EvpPkeyEC     = 408
	EvpPkeyX25519 = 1034
	EvpPkeyED25519 = 1087
	EvpPkeyED448  = 1088
	EvpPkeySM2    = 1172
)

// EVP_PKEY_get_base_id 返回密钥底层类型 ID（如 EvpPkeyEC）。
// EVP_PKEY_get_base_id returns the underlying algorithm type of pkey; SM2
// keys report EvpPkeyEC here (use EVP_PKEY_get_id for EvpPkeySM2).
func EVP_PKEY_get_base_id(pkey unsafe.Pointer) int {
	return int(C.EVP_PKEY_get_base_id((*C.EVP_PKEY)(pkey)))
}

// EVP_PKEY_get_id 返回密钥完整类型 ID（如 SM2 密钥返回 EvpPkeySM2）。
// EVP_PKEY_get_id returns the full type ID; for SM2 keys this returns
// EvpPkeySM2 rather than the base EC ID.
func EVP_PKEY_get_id(pkey unsafe.Pointer) int {
	return int(C.EVP_PKEY_get_id((*C.EVP_PKEY)(pkey)))
}

// EVP_PKEY_CTX_new_from_pkey 基于密钥创建操作上下文。
// EVP_PKEY_CTX_new_from_pkey allocates a new EVP_PKEY_CTX bound to pkey
// (no ENGINE). The caller owns the returned ctx and must release it with
// EVP_PKEY_CTX_free.
func EVP_PKEY_CTX_new_from_pkey(pkey unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.EVP_PKEY_CTX_new_from_pkey(nil, (*C.EVP_PKEY)(pkey), nil))
}

// EVP_PKEY_CTX_free 释放操作上下文。
// EVP_PKEY_CTX_free releases ctx. Safe on NULL; the pointer must not be
// used after free.
func EVP_PKEY_CTX_free(ctx unsafe.Pointer) {
	C.EVP_PKEY_CTX_free((*C.EVP_PKEY_CTX)(ctx))
}

// EVP_PKEY_encrypt_init 初始化加密上下文。
// EVP_PKEY_encrypt_init prepares ctx for a public-key encrypt operation.
// Returns true on success.
func EVP_PKEY_encrypt_init(ctx unsafe.Pointer) bool {
	return C.EVP_PKEY_encrypt_init((*C.EVP_PKEY_CTX)(ctx)) == 1
}

// EVP_PKEY_encrypt 加密数据（SM2 输出为 ASN.1 DER，含 C1C3C2）。
// 注意：*outlen 为容量入/实际出，实际调用时必须把缓冲容量传入。
// EVP_PKEY_encrypt encrypts in. *outl is BOTH an input (capacity of out) and
// an output (actual ciphertext length) parameter; callers MUST pre-size the
// buffer (or pass out=nil to query the required length first). For SM2 the
// ciphertext is ASN.1 DER (C1C3C2 concatenation).
func EVP_PKEY_encrypt(ctx unsafe.Pointer, out, in []byte, outl *int) bool {
	var l C.size_t
	if len(out) > 0 {
		l = C.size_t(len(out)) // 输入容量
	}
	var ok bool
	switch {
	case len(in) == 0 && len(out) == 0:
		ok = C.EVP_PKEY_encrypt((*C.EVP_PKEY_CTX)(ctx), nil, &l, nil, 0) == 1
	case len(in) == 0:
		ok = C.EVP_PKEY_encrypt((*C.EVP_PKEY_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l, nil, 0) == 1
	case len(out) == 0:
		ok = C.EVP_PKEY_encrypt((*C.EVP_PKEY_CTX)(ctx), nil, &l,
			(*C.uchar)(unsafe.Pointer(&in[0])), C.size_t(len(in))) == 1
	default:
		ok = C.EVP_PKEY_encrypt((*C.EVP_PKEY_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l,
			(*C.uchar)(unsafe.Pointer(&in[0])), C.size_t(len(in))) == 1
	}
	if outl != nil {
		*outl = int(l)
	}
	return ok
}

// EVP_PKEY_decrypt_init 初始化解密上下文。
// EVP_PKEY_decrypt_init prepares ctx for a public-key decrypt operation.
// Returns true on success.
func EVP_PKEY_decrypt_init(ctx unsafe.Pointer) bool {
	return C.EVP_PKEY_decrypt_init((*C.EVP_PKEY_CTX)(ctx)) == 1
}

// EVP_PKEY_decrypt 解密数据。*outlen 为容量入/实际出。
// EVP_PKEY_decrypt decrypts in. *outl is BOTH an input (capacity of out) and
// an output (actual plaintext length) parameter.
func EVP_PKEY_decrypt(ctx unsafe.Pointer, out, in []byte, outl *int) bool {
	var l C.size_t
	if len(out) > 0 {
		l = C.size_t(len(out)) // 输入容量
	}
	var ok bool
	switch {
	case len(in) == 0 && len(out) == 0:
		ok = C.EVP_PKEY_decrypt((*C.EVP_PKEY_CTX)(ctx), nil, &l, nil, 0) == 1
	case len(in) == 0:
		ok = C.EVP_PKEY_decrypt((*C.EVP_PKEY_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l, nil, 0) == 1
	case len(out) == 0:
		ok = C.EVP_PKEY_decrypt((*C.EVP_PKEY_CTX)(ctx), nil, &l,
			(*C.uchar)(unsafe.Pointer(&in[0])), C.size_t(len(in))) == 1
	default:
		ok = C.EVP_PKEY_decrypt((*C.EVP_PKEY_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l,
			(*C.uchar)(unsafe.Pointer(&in[0])), C.size_t(len(in))) == 1
	}
	if outl != nil {
		*outl = int(l)
	}
	return ok
}

// EVP_DigestSignInit 初始化签名上下文，返回内部 EVP_PKEY_CTX（由 MD_CTX 拥有，勿单独释放）。
// EVP_DigestSignInit sets up ctx (an EVP_MD_CTX) for signing with digest md
// and key pkey. It returns (true, pctx) on success where pctx is the inner
// EVP_PKEY_CTX owned by the MD_CTX; do NOT free pctx separately.
func EVP_DigestSignInit(ctx, md, e, pkey unsafe.Pointer) (bool, unsafe.Pointer) {
	var pctx *C.EVP_PKEY_CTX
	ok := C.EVP_DigestSignInit((*C.EVP_MD_CTX)(ctx), &pctx, (*C.EVP_MD)(md),
		(*C.ENGINE)(e), (*C.EVP_PKEY)(pkey)) == 1
	return ok, unsafe.Pointer(pctx)
}

// EVP_DigestVerifyInit 初始化验签上下文，返回内部 EVP_PKEY_CTX（由 MD_CTX 拥有）。
// EVP_DigestVerifyInit sets up ctx (an EVP_MD_CTX) for verification. The
// returned pctx is owned by the MD_CTX and must NOT be freed separately.
func EVP_DigestVerifyInit(ctx, md, e, pkey unsafe.Pointer) (bool, unsafe.Pointer) {
	var pctx *C.EVP_PKEY_CTX
	ok := C.EVP_DigestVerifyInit((*C.EVP_MD_CTX)(ctx), &pctx, (*C.EVP_MD)(md),
		(*C.ENGINE)(e), (*C.EVP_PKEY)(pkey)) == 1
	return ok, unsafe.Pointer(pctx)
}

// EVP_PKEY_CTX_set1_id 设置 SM2 用户标识（userId）。
// EVP_PKEY_CTX_set1_id configures the SM2 user identifier (default is the
// 16-byte "1234567812345678" string when never set). Must be called before
// sign / verify on the SM2 pctx.
func EVP_PKEY_CTX_set1_id(pctx unsafe.Pointer, id []byte) bool {
	if len(id) == 0 {
		return C.EVP_PKEY_CTX_set1_id((*C.EVP_PKEY_CTX)(pctx), nil, 0) == 1
	}
	return C.EVP_PKEY_CTX_set1_id((*C.EVP_PKEY_CTX)(pctx),
		unsafe.Pointer(&id[0]), C.int(len(id))) == 1
}

// EVP_PKEY_size 返回密钥的最大签名/加密输出长度（字节）。
// EVP_PKEY_size returns the maximum output length in bytes for the largest
// sign / encrypt operation that pkey can produce.
func EVP_PKEY_size(pkey unsafe.Pointer) int {
	return int(C.EVP_PKEY_size((*C.EVP_PKEY)(pkey)))
}

// EVP_DigestSignUpdate 追加数据到签名上下文（const void * → unsafe.Pointer）。
// EVP_DigestSignUpdate feeds data into the running sign context; the C
// signature uses const void * which cgo maps to unsafe.Pointer.
func EVP_DigestSignUpdate(ctx unsafe.Pointer, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	return C.EVP_DigestSignUpdate((*C.EVP_MD_CTX)(ctx),
		unsafe.Pointer(&data[0]), C.size_t(len(data))) == 1
}

// EVP_DigestSignFinal 完成签名，写入 sig，实际长度通过 siglen 返回。
// 注意：*siglen 为容量入/实际出，须传入缓冲容量。
// EVP_DigestSignFinal produces the signature into sig. *siglen is BOTH an
// input (capacity) and output (actual signature length); callers MUST
// pre-size the buffer (or pass sig=nil to query the required length first).
func EVP_DigestSignFinal(ctx unsafe.Pointer, sig []byte, siglen *int) bool {
	var l C.size_t
	if len(sig) > 0 {
		l = C.size_t(len(sig)) // 输入容量
	}
	var ok bool
	if len(sig) == 0 {
		ok = C.EVP_DigestSignFinal((*C.EVP_MD_CTX)(ctx), nil, &l) == 1
	} else {
		ok = C.EVP_DigestSignFinal((*C.EVP_MD_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&sig[0])), &l) == 1
	}
	if siglen != nil {
		*siglen = int(l)
	}
	return ok
}

// EVP_DigestVerifyUpdate 追加数据到验签上下文。
// EVP_DigestVerifyUpdate feeds data into the running verify context; an
// empty data slice returns true without calling the C layer.
func EVP_DigestVerifyUpdate(ctx unsafe.Pointer, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	return C.EVP_DigestVerifyUpdate((*C.EVP_MD_CTX)(ctx),
		unsafe.Pointer(&data[0]), C.size_t(len(data))) == 1
}

// EVP_DigestVerifyFinal 校验签名。
// EVP_DigestVerifyFinal validates sig against the data accumulated so far.
// Returns true if the signature is valid, false otherwise.
func EVP_DigestVerifyFinal(ctx unsafe.Pointer, sig []byte) bool {
	if len(sig) == 0 {
		return C.EVP_DigestVerifyFinal((*C.EVP_MD_CTX)(ctx), nil, 0) == 1
	}
	return C.EVP_DigestVerifyFinal((*C.EVP_MD_CTX)(ctx),
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig))) == 1
}

// RSA 填充常量（来自 rsa.h 宏）。
//
// RsaPaddingPKCS1, RsaPaddingOAEP, RsaPaddingPSS are the RSA padding modes
// accepted by EVP_PKEY_CTX_set_rsa_padding; RsaPssSaltLenDigest/Auto/Max are
// the special salt-length sentinels for RSA-PSS.
const (
	RsaPaddingPKCS1     = 1
	RsaPaddingOAEP      = 4
	RsaPaddingPSS       = 6
	RsaPssSaltLenDigest = -1
	RsaPssSaltLenAuto   = -2
	RsaPssSaltLenMax    = -3
)

// X_EVP_PKEY_Q_keygen_rsa 生成 RSA 密钥对（bits 为模数位数，如 2048）。
// X_EVP_PKEY_Q_keygen_rsa (shim) generates an RSA key pair of modulus size
// bits (e.g. 2048, 3072, 4096). The caller owns the returned EVP_PKEY.
func X_EVP_PKEY_Q_keygen_rsa(bits int) unsafe.Pointer {
	return unsafe.Pointer(C.X_EVP_PKEY_Q_keygen_rsa(C.int(bits)))
}

// X_EVP_PKEY_Q_keygen_ec 生成 EC 密钥对（curve 如 "prime256v1"、"secp384r1"）。
// X_EVP_PKEY_Q_keygen_ec (shim) generates an EC key pair on the named curve
// (e.g. "prime256v1", "secp384r1", "secp521r1"). The caller owns the EVP_PKEY.
func X_EVP_PKEY_Q_keygen_ec(curve string) unsafe.Pointer {
	c := C.CString(curve)
	defer C.free(unsafe.Pointer(c))
	return unsafe.Pointer(C.X_EVP_PKEY_Q_keygen_ec(c))
}

// X_EVP_PKEY_Q_keygen_ed25519 生成 Ed25519 密钥对（RFC 8032）。
// X_EVP_PKEY_Q_keygen_ed25519 (shim) generates an Ed25519 signing key pair.
// The caller owns the returned EVP_PKEY and must release it with EVP_PKEY_free.
func X_EVP_PKEY_Q_keygen_ed25519() unsafe.Pointer {
	return unsafe.Pointer(C.X_EVP_PKEY_Q_keygen_ed25519())
}

// X_EVP_PKEY_Q_keygen_ed448 生成 Ed448 密钥对（RFC 8032）。
// X_EVP_PKEY_Q_keygen_ed448 (shim) generates an Ed448 signing key pair.
// The caller owns the returned EVP_PKEY and must release it with EVP_PKEY_free.
func X_EVP_PKEY_Q_keygen_ed448() unsafe.Pointer {
	return unsafe.Pointer(C.X_EVP_PKEY_Q_keygen_ed448())
}

// X_EVP_PKEY_Q_keygen_x25519 生成 X25519 密钥对（RFC 7748）。
// X_EVP_PKEY_Q_keygen_x25519 (shim) generates an X25519 ECDH key pair.
// The caller owns the returned EVP_PKEY and must release it with EVP_PKEY_free.
func X_EVP_PKEY_Q_keygen_x25519() unsafe.Pointer {
	return unsafe.Pointer(C.X_EVP_PKEY_Q_keygen_x25519())
}

// X_PEM_read_bio_PrivateKey_pass 从 BIO 读取用口令加密的 PEM 私钥。
// X_PEM_read_bio_PrivateKey_pass (shim) reads an encrypted PEM private key
// from bio using pass. Returns NULL on failure; caller owns the EVP_PKEY.
func X_PEM_read_bio_PrivateKey_pass(bio unsafe.Pointer, pass string) unsafe.Pointer {
	c := C.CString(pass)
	defer C.free(unsafe.Pointer(c))
	return unsafe.Pointer(C.X_PEM_read_bio_PrivateKey_pass((*C.BIO)(bio), c))
}

// X_PEM_write_bio_PrivateKey_enc 将私钥以 AES-256-CBC 加密写入 PEM。
// X_PEM_write_bio_PrivateKey_enc (shim) writes pkey to bio as a password-
// protected PEM using AES-256-CBC. Returns true on success.
func X_PEM_write_bio_PrivateKey_enc(bio, pkey unsafe.Pointer, pass string) bool {
	c := C.CString(pass)
	defer C.free(unsafe.Pointer(c))
	return C.X_PEM_write_bio_PrivateKey_enc((*C.BIO)(bio), (*C.EVP_PKEY)(pkey), c) == 1
}

// X_PEM_read_bio_RSAPrivateKey 从 BIO 读取 PKCS#1 PEM 私钥（返回 RSA*）。
// X_PEM_read_bio_RSAPrivateKey (shim) reads a PKCS#1 PEM-encoded RSA private
// key from bio and returns a legacy RSA* pointer. Caller owns it and must
// release with RSA_free (or wrap with EVP_PKEY and free the wrapper).
func X_PEM_read_bio_RSAPrivateKey(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_RSAPrivateKey((*C.BIO)(bio)))
}

// X_PEM_write_bio_RSAPrivateKey 将 RSA* 以 PKCS#1 PEM 写入 BIO。
// X_PEM_write_bio_RSAPrivateKey (shim) writes the legacy RSA* to bio as a
// PKCS#1 PEM. Returns true on success.
func X_PEM_write_bio_RSAPrivateKey(bio, rsa unsafe.Pointer) bool {
	return C.X_PEM_write_bio_RSAPrivateKey((*C.BIO)(bio), (*C.RSA)(rsa)) == 1
}

// RSA_free 释放 RSA 对象。
// RSA_free releases a legacy RSA*. Safe on NULL; the pointer must not be
// used after free.
func RSA_free(rsa unsafe.Pointer) {
	C.RSA_free((*C.RSA)(rsa))
}

// EVP_PKEY_dup 复制密钥（返回新引用，调用方负责 EVP_PKEY_free）。
// EVP_PKEY_dup returns a new EVP_PKEY reference that is independent of the
// input; the caller MUST release it with EVP_PKEY_free.
func EVP_PKEY_dup(pkey unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.EVP_PKEY_dup((*C.EVP_PKEY)(pkey)))
}

// EVP_PKEY_eq 比较两个密钥是否等价（1=相等，0=不等，-1=错误）。
// EVP_PKEY_eq compares a and b: 1 means equivalent (same algorithm and
// matching public/private material), 0 means not equivalent, -1 indicates
// an error (consult the OpenSSL error queue).
func EVP_PKEY_eq(a, b unsafe.Pointer) int {
	return int(C.EVP_PKEY_eq((*C.EVP_PKEY)(a), (*C.EVP_PKEY)(b)))
}

// I2d_PUBKEY 将公钥编码为 DER（SubjectPublicKeyInfo）。
// I2d_PUBKEY serializes pkey to DER (SubjectPublicKeyInfo). Returns
// (bytes, true) on success or (nil, false) when the encoder reports a
// non-positive length.
func I2d_PUBKEY(pkey unsafe.Pointer) ([]byte, bool) {
	n := C.i2d_PUBKEY((*C.EVP_PKEY)(pkey), nil)
	if n <= 0 {
		return nil, false
	}
	buf := C.malloc(C.size_t(n))
	if buf == nil {
		return nil, false
	}
	defer C.free(buf)
	p := (*C.uchar)(buf)
	C.i2d_PUBKEY((*C.EVP_PKEY)(pkey), &p)
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), true
}

// EVP_PKEY_get_bn_param 返回密钥的大数参数（如 RSA "n"/"e"/"d"/"p"/"q"；EC "d"），
// 以大端字节返回；参数不存在返回 ok=false。
// EVP_PKEY_get_bn_param returns the named big-number parameter of pkey as
// big-endian bytes (e.g. RSA "n"/"e"/"d"/"p"/"q", EC "d"). Returns
// (nil, false) when the parameter is not present or the call fails.
func EVP_PKEY_get_bn_param(pkey unsafe.Pointer, name string) ([]byte, bool) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	var bn *C.BIGNUM
	if C.EVP_PKEY_get_bn_param((*C.EVP_PKEY)(pkey), cName, &bn) != 1 {
		return nil, false
	}
	defer C.BN_free(bn)
	// BN_num_bytes 为宏（(bits+7)/8），改用函数 BN_num_bits。
	n := (C.BN_num_bits(bn) + 7) / 8
	if n <= 0 {
		return nil, false
	}
	out := make([]byte, n)
	C.BN_bn2bin(bn, (*C.uchar)(unsafe.Pointer(&out[0])))
	return out, true
}

// EVP_PKEY_get_utf8_string_param 返回密钥的 UTF-8 字符串参数（如 EC "group"）。
// EVP_PKEY_get_utf8_string_param returns a named UTF-8 string parameter
// (e.g. EC "group" -> curve name); the internal buffer is 64 bytes, so
// values longer than that are truncated. Returns ("", false) on failure.
func EVP_PKEY_get_utf8_string_param(pkey unsafe.Pointer, name string) (string, bool) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	var buf [64]C.char
	var outlen C.size_t
	if C.EVP_PKEY_get_utf8_string_param((*C.EVP_PKEY)(pkey), cName,
		&buf[0], C.size_t(len(buf)), &outlen) != 1 {
		return "", false
	}
	return C.GoString(&buf[0]), true
}

// EVP_PKEY_get_octet_string_param 返回密钥的字节串参数（如 EC "pub" 未压缩点）。
// EVP_PKEY_get_octet_string_param returns a named raw-byte parameter
// (e.g. EC "pub" -> uncompressed public point); the internal buffer is
// 256 bytes. Returns (nil, false) on failure.
func EVP_PKEY_get_octet_string_param(pkey unsafe.Pointer, name string) ([]byte, bool) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	var buf [256]C.uchar
	var outlen C.size_t
	if C.EVP_PKEY_get_octet_string_param((*C.EVP_PKEY)(pkey), cName,
		&buf[0], C.size_t(len(buf)), &outlen) != 1 {
		return nil, false
	}
	return C.GoBytes(unsafe.Pointer(&buf[0]), C.int(outlen)), true
}

// EVP_PKEY_CTX_set_rsa_padding 设置 RSA 填充模式。
// EVP_PKEY_CTX_set_rsa_padding sets the RSA padding mode; pad is one of
// RsaPaddingPKCS1, RsaPaddingOAEP, RsaPaddingPSS.
func EVP_PKEY_CTX_set_rsa_padding(ctx unsafe.Pointer, pad int) bool {
	return C.EVP_PKEY_CTX_set_rsa_padding((*C.EVP_PKEY_CTX)(ctx), C.int(pad)) == 1
}

// EVP_PKEY_CTX_set_rsa_pss_saltlen 设置 RSA-PSS 盐长。
// EVP_PKEY_CTX_set_rsa_pss_saltlen sets the RSA-PSS salt length; pass one
// of the RsaPssSaltLen* sentinels or a positive integer.
func EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx unsafe.Pointer, saltlen int) bool {
	return C.EVP_PKEY_CTX_set_rsa_pss_saltlen((*C.EVP_PKEY_CTX)(ctx), C.int(saltlen)) == 1
}

// EVP_PKEY_CTX_set_rsa_mgf1_md 设置 RSA MGF1 摘要。
// EVP_PKEY_CTX_set_rsa_mgf1_md sets the MGF1 digest used inside RSA-PSS
// (and optionally RSA-OAEP).
func EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md unsafe.Pointer) bool {
	return C.EVP_PKEY_CTX_set_rsa_mgf1_md((*C.EVP_PKEY_CTX)(ctx), (*C.EVP_MD)(md)) == 1
}

// EVP_PKEY_CTX_set_rsa_oaep_md 设置 RSA-OAEP 摘要。
// EVP_PKEY_CTX_set_rsa_oaep_md sets the OAEP label digest used inside RSA.
func EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md unsafe.Pointer) bool {
	return C.EVP_PKEY_CTX_set_rsa_oaep_md((*C.EVP_PKEY_CTX)(ctx), (*C.EVP_MD)(md)) == 1
}

// I2d_PrivateKey 将私钥编码为传统 DER（RSA 为 PKCS#1）。
// I2d_PrivateKey serializes pkey to traditional (legacy) DER; for RSA keys
// this is PKCS#1 RSAPrivateKey, NOT PKCS#8. Returns (bytes, true) on
// success or (nil, false) on encoder failure.
func I2d_PrivateKey(pkey unsafe.Pointer) ([]byte, bool) {
	n := C.i2d_PrivateKey((*C.EVP_PKEY)(pkey), nil)
	if n <= 0 {
		return nil, false
	}
	buf := C.malloc(C.size_t(n))
	if buf == nil {
		return nil, false
	}
	defer C.free(buf)
	p := (*C.uchar)(buf)
	C.i2d_PrivateKey((*C.EVP_PKEY)(pkey), &p)
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), true
}

// D2i_PrivateKey 从传统 DER 解析私钥（type=0 自动识别）。
// D2i_PrivateKey parses a private key from traditional DER; type=0 lets
// OpenSSL auto-detect the key algorithm. Returns NULL on empty input or
// parse failure; caller owns the EVP_PKEY.
func D2i_PrivateKey(der []byte) unsafe.Pointer {
	if len(der) == 0 {
		return nil
	}
	buf := C.malloc(C.size_t(len(der)))
	if buf == nil {
		return nil
	}
	defer C.free(buf)
	C.memcpy(buf, unsafe.Pointer(&der[0]), C.size_t(len(der)))
	p := (*C.uchar)(buf)
	return unsafe.Pointer(C.d2i_PrivateKey(0, nil, &p, C.long(len(der))))
}

// EVP_PKEY_new_raw_private_key 从原始私钥字节构造密钥（Ed25519=32B，Ed448=57B，X25519=32B）。
// EVP_PKEY_new_raw_private_key wraps raw private-key bytes into an EVP_PKEY.
// type must be one of EvpPkeyED25519 / EvpPkeyED448 / EvpPkeyX25519. The
// caller owns the returned EVP_PKEY and must release it with EVP_PKEY_free.
func EVP_PKEY_new_raw_private_key(typeID int, raw []byte) unsafe.Pointer {
	if len(raw) == 0 {
		return nil
	}
	return unsafe.Pointer(C.EVP_PKEY_new_raw_private_key(C.int(typeID), nil,
		(*C.uchar)(unsafe.Pointer(&raw[0])), C.size_t(len(raw))))
}

// EVP_PKEY_new_raw_public_key 从原始公钥字节构造密钥（Ed25519=32B，Ed448=57B，X25519=32B）。
// EVP_PKEY_new_raw_public_key wraps raw public-key bytes into an EVP_PKEY.
// type must be one of EvpPkeyED25519 / EvpPkeyED448 / EvpPkeyX25519. The
// caller owns the returned EVP_PKEY and must release it with EVP_PKEY_free.
func EVP_PKEY_new_raw_public_key(typeID int, raw []byte) unsafe.Pointer {
	if len(raw) == 0 {
		return nil
	}
	return unsafe.Pointer(C.EVP_PKEY_new_raw_public_key(C.int(typeID), nil,
		(*C.uchar)(unsafe.Pointer(&raw[0])), C.size_t(len(raw))))
}

// EVP_PKEY_get_raw_private_key 导出原始私钥字节。两段式：raw=nil 时查询所需长度；
// raw 非 nil 时写入预分配缓冲。铜锁 EdDSA provider 在 buffer 过小时直接报错，因此调用方
// 通常先 query 再按返回值分配写入（不允许猜容量）。
// 返回 (length, true) 成功；失败返回 (0, false)。
//
// EVP_PKEY_get_raw_private_key exports raw private-key bytes using a
// two-call pattern: pass raw=nil to query the required length, then call
// again with a pre-sized buffer of that length. The Tongsuo EdDSA
// provider rejects undersized buffers outright, so callers must not guess.
// Returns (length, true) on success; on failure (0, false).
func EVP_PKEY_get_raw_private_key(pkey unsafe.Pointer, raw []byte) (int, bool) {
	var (
		buf *C.uchar
		n   C.size_t
	)
	if len(raw) > 0 {
		buf = (*C.uchar)(unsafe.Pointer(&raw[0]))
		n = C.size_t(len(raw))
	}
	if C.EVP_PKEY_get_raw_private_key((*C.EVP_PKEY)(pkey), buf, &n) != 1 {
		return 0, false
	}
	return int(n), true
}

// EVP_PKEY_get_raw_public_key 导出原始公钥字节；语义同 EVP_PKEY_get_raw_private_key。
// EVP_PKEY_get_raw_public_key exports raw public-key bytes; semantics
// match EVP_PKEY_get_raw_private_key (two-call: query then fill).
func EVP_PKEY_get_raw_public_key(pkey unsafe.Pointer, raw []byte) (int, bool) {
	var (
		buf *C.uchar
		n   C.size_t
	)
	if len(raw) > 0 {
		buf = (*C.uchar)(unsafe.Pointer(&raw[0]))
		n = C.size_t(len(raw))
	}
	if C.EVP_PKEY_get_raw_public_key((*C.EVP_PKEY)(pkey), buf, &n) != 1 {
		return 0, false
	}
	return int(n), true
}

// EVP_PKEY_derive_init 初始化密钥协商上下文。
// EVP_PKEY_derive_init prepares ctx for a key-agreement (DH/KEM) operation.
// Returns true on success.
func EVP_PKEY_derive_init(ctx unsafe.Pointer) bool {
	return C.EVP_PKEY_derive_init((*C.EVP_PKEY_CTX)(ctx)) == 1
}

// EVP_PKEY_derive_set_peer 设置对端公钥（用于 X25519 等 ECDH）。
// EVP_PKEY_derive_set_peer attaches peer as the remote public key for the
// upcoming derive; returns true on success.
func EVP_PKEY_derive_set_peer(ctx, peer unsafe.Pointer) bool {
	return C.EVP_PKEY_derive_set_peer((*C.EVP_PKEY_CTX)(ctx), (*C.EVP_PKEY)(peer)) == 1
}

// EVP_PKEY_derive 计算共享密钥（X25519 输出 32B）。out 容量足够时直接写入；out=nil 时
// 通过 *keylen 返回所需容量。调用方按需预分配或两段式查询。
// EVP_PKEY_derive computes the shared secret. When out is non-nil it must be
// pre-sized; when out is nil *keylen returns the required capacity. Callers
// typically call it twice: once with out=nil to query, once with a sized
// buffer to fill.
func EVP_PKEY_derive(ctx unsafe.Pointer, out []byte, keylen *int) bool {
	var l C.size_t
	if len(out) > 0 {
		l = C.size_t(len(out))
	}
	var ok bool
	if len(out) == 0 {
		ok = C.EVP_PKEY_derive((*C.EVP_PKEY_CTX)(ctx), nil, &l) == 1
	} else {
		ok = C.EVP_PKEY_derive((*C.EVP_PKEY_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l) == 1
	}
	if keylen != nil {
		*keylen = int(l)
	}
	return ok
}
