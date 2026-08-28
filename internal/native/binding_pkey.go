package native

/*
#include <openssl/evp.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// X_EVP_PKEY_Q_keygen_sm2 生成 SM2 密钥对（经 shim 包装可变参函数）。
func X_EVP_PKEY_Q_keygen_sm2() unsafe.Pointer {
	return unsafe.Pointer(C.X_EVP_PKEY_Q_keygen_sm2())
}

// X_PEM_read_bio_PrivateKey 从 BIO 读取 PEM 私钥（PKCS#8）。
func X_PEM_read_bio_PrivateKey(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_PrivateKey((*C.BIO)(bio)))
}

// X_PEM_write_bio_PrivateKey 将私钥以 PEM（PKCS#8）写入 BIO。
func X_PEM_write_bio_PrivateKey(bio unsafe.Pointer, pkey unsafe.Pointer) bool {
	return C.X_PEM_write_bio_PrivateKey((*C.BIO)(bio), (*C.EVP_PKEY)(pkey)) == 1
}

// X_PEM_read_bio_PUBKEY 从 BIO 读取 PEM 公钥（SubjectPublicKeyInfo）。
func X_PEM_read_bio_PUBKEY(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_PUBKEY((*C.BIO)(bio)))
}

// X_PEM_write_bio_PUBKEY 将公钥以 PEM（SubjectPublicKeyInfo）写入 BIO。
func X_PEM_write_bio_PUBKEY(bio unsafe.Pointer, pkey unsafe.Pointer) bool {
	return C.X_PEM_write_bio_PUBKEY((*C.BIO)(bio), (*C.EVP_PKEY)(pkey)) == 1
}

// EVP_PKEY_free 释放密钥对象。
func EVP_PKEY_free(pkey unsafe.Pointer) {
	C.EVP_PKEY_free((*C.EVP_PKEY)(pkey))
}

// EVP_PKEY 类型常量（来自 evp.h 宏，OpenSSL 3.x / 铜锁）。
const (
	EvpPkeyRSA = 6
	EvpPkeyDSA = 116
	EvpPkeyEC  = 408
	EvpPkeySM2 = 1172
)

// EVP_PKEY_get_base_id 返回密钥底层类型 ID（如 EvpPkeyEC）。
func EVP_PKEY_get_base_id(pkey unsafe.Pointer) int {
	return int(C.EVP_PKEY_get_base_id((*C.EVP_PKEY)(pkey)))
}

// EVP_PKEY_get_id 返回密钥完整类型 ID（如 SM2 密钥返回 EvpPkeySM2）。
func EVP_PKEY_get_id(pkey unsafe.Pointer) int {
	return int(C.EVP_PKEY_get_id((*C.EVP_PKEY)(pkey)))
}

// EVP_PKEY_CTX_new_from_pkey 基于密钥创建操作上下文。
func EVP_PKEY_CTX_new_from_pkey(pkey unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.EVP_PKEY_CTX_new_from_pkey(nil, (*C.EVP_PKEY)(pkey), nil))
}

// EVP_PKEY_CTX_free 释放操作上下文。
func EVP_PKEY_CTX_free(ctx unsafe.Pointer) {
	C.EVP_PKEY_CTX_free((*C.EVP_PKEY_CTX)(ctx))
}

// EVP_PKEY_encrypt_init 初始化加密上下文。
func EVP_PKEY_encrypt_init(ctx unsafe.Pointer) bool {
	return C.EVP_PKEY_encrypt_init((*C.EVP_PKEY_CTX)(ctx)) == 1
}

// EVP_PKEY_encrypt 加密数据（SM2 输出为 ASN.1 DER，含 C1C3C2）。
// 注意：*outlen 为容量入/实际出，实际调用时必须把缓冲容量传入。
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
func EVP_PKEY_decrypt_init(ctx unsafe.Pointer) bool {
	return C.EVP_PKEY_decrypt_init((*C.EVP_PKEY_CTX)(ctx)) == 1
}

// EVP_PKEY_decrypt 解密数据。*outlen 为容量入/实际出。
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
func EVP_DigestSignInit(ctx, md, e, pkey unsafe.Pointer) (bool, unsafe.Pointer) {
	var pctx *C.EVP_PKEY_CTX
	ok := C.EVP_DigestSignInit((*C.EVP_MD_CTX)(ctx), &pctx, (*C.EVP_MD)(md),
		(*C.ENGINE)(e), (*C.EVP_PKEY)(pkey)) == 1
	return ok, unsafe.Pointer(pctx)
}

// EVP_DigestVerifyInit 初始化验签上下文，返回内部 EVP_PKEY_CTX（由 MD_CTX 拥有）。
func EVP_DigestVerifyInit(ctx, md, e, pkey unsafe.Pointer) (bool, unsafe.Pointer) {
	var pctx *C.EVP_PKEY_CTX
	ok := C.EVP_DigestVerifyInit((*C.EVP_MD_CTX)(ctx), &pctx, (*C.EVP_MD)(md),
		(*C.ENGINE)(e), (*C.EVP_PKEY)(pkey)) == 1
	return ok, unsafe.Pointer(pctx)
}

// EVP_PKEY_CTX_set1_id 设置 SM2 用户标识（userId）。
func EVP_PKEY_CTX_set1_id(pctx unsafe.Pointer, id []byte) bool {
	if len(id) == 0 {
		return C.EVP_PKEY_CTX_set1_id((*C.EVP_PKEY_CTX)(pctx), nil, 0) == 1
	}
	return C.EVP_PKEY_CTX_set1_id((*C.EVP_PKEY_CTX)(pctx),
		unsafe.Pointer(&id[0]), C.int(len(id))) == 1
}

// EVP_PKEY_size 返回密钥的最大签名/加密输出长度（字节）。
func EVP_PKEY_size(pkey unsafe.Pointer) int {
	return int(C.EVP_PKEY_size((*C.EVP_PKEY)(pkey)))
}

// EVP_DigestSignUpdate 追加数据到签名上下文（const void * → unsafe.Pointer）。
func EVP_DigestSignUpdate(ctx unsafe.Pointer, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	return C.EVP_DigestSignUpdate((*C.EVP_MD_CTX)(ctx),
		unsafe.Pointer(&data[0]), C.size_t(len(data))) == 1
}

// EVP_DigestSignFinal 完成签名，写入 sig，实际长度通过 siglen 返回。
// 注意：*siglen 为容量入/实际出，须传入缓冲容量。
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
func EVP_DigestVerifyUpdate(ctx unsafe.Pointer, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	return C.EVP_DigestVerifyUpdate((*C.EVP_MD_CTX)(ctx),
		unsafe.Pointer(&data[0]), C.size_t(len(data))) == 1
}

// EVP_DigestVerifyFinal 校验签名。
func EVP_DigestVerifyFinal(ctx unsafe.Pointer, sig []byte) bool {
	if len(sig) == 0 {
		return C.EVP_DigestVerifyFinal((*C.EVP_MD_CTX)(ctx), nil, 0) == 1
	}
	return C.EVP_DigestVerifyFinal((*C.EVP_MD_CTX)(ctx),
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig))) == 1
}

// RSA 填充常量（来自 rsa.h 宏）。
const (
	RsaPaddingPKCS1     = 1
	RsaPaddingOAEP      = 4
	RsaPaddingPSS       = 6
	RsaPssSaltLenDigest = -1
	RsaPssSaltLenAuto   = -2
	RsaPssSaltLenMax    = -3
)

// X_EVP_PKEY_Q_keygen_rsa 生成 RSA 密钥对（bits 为模数位数，如 2048）。
func X_EVP_PKEY_Q_keygen_rsa(bits int) unsafe.Pointer {
	return unsafe.Pointer(C.X_EVP_PKEY_Q_keygen_rsa(C.int(bits)))
}

// X_EVP_PKEY_Q_keygen_ec 生成 EC 密钥对（curve 如 "prime256v1"、"secp384r1"）。
func X_EVP_PKEY_Q_keygen_ec(curve string) unsafe.Pointer {
	c := C.CString(curve)
	defer C.free(unsafe.Pointer(c))
	return unsafe.Pointer(C.X_EVP_PKEY_Q_keygen_ec(c))
}

// X_PEM_read_bio_PrivateKey_pass 从 BIO 读取用口令加密的 PEM 私钥。
func X_PEM_read_bio_PrivateKey_pass(bio unsafe.Pointer, pass string) unsafe.Pointer {
	c := C.CString(pass)
	defer C.free(unsafe.Pointer(c))
	return unsafe.Pointer(C.X_PEM_read_bio_PrivateKey_pass((*C.BIO)(bio), c))
}

// X_PEM_write_bio_PrivateKey_enc 将私钥以 AES-256-CBC 加密写入 PEM。
func X_PEM_write_bio_PrivateKey_enc(bio, pkey unsafe.Pointer, pass string) bool {
	c := C.CString(pass)
	defer C.free(unsafe.Pointer(c))
	return C.X_PEM_write_bio_PrivateKey_enc((*C.BIO)(bio), (*C.EVP_PKEY)(pkey), c) == 1
}

// X_PEM_read_bio_RSAPrivateKey 从 BIO 读取 PKCS#1 PEM 私钥（返回 RSA*）。
func X_PEM_read_bio_RSAPrivateKey(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_RSAPrivateKey((*C.BIO)(bio)))
}

// X_PEM_write_bio_RSAPrivateKey 将 RSA* 以 PKCS#1 PEM 写入 BIO。
func X_PEM_write_bio_RSAPrivateKey(bio, rsa unsafe.Pointer) bool {
	return C.X_PEM_write_bio_RSAPrivateKey((*C.BIO)(bio), (*C.RSA)(rsa)) == 1
}

// RSA_free 释放 RSA 对象。
func RSA_free(rsa unsafe.Pointer) {
	C.RSA_free((*C.RSA)(rsa))
}

// EVP_PKEY_dup 复制密钥（返回新引用，调用方负责 EVP_PKEY_free）。
func EVP_PKEY_dup(pkey unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.EVP_PKEY_dup((*C.EVP_PKEY)(pkey)))
}

// EVP_PKEY_eq 比较两个密钥是否等价（1=相等，0=不等，-1=错误）。
func EVP_PKEY_eq(a, b unsafe.Pointer) int {
	return int(C.EVP_PKEY_eq((*C.EVP_PKEY)(a), (*C.EVP_PKEY)(b)))
}

// I2d_PUBKEY 将公钥编码为 DER（SubjectPublicKeyInfo）。
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
func EVP_PKEY_CTX_set_rsa_padding(ctx unsafe.Pointer, pad int) bool {
	return C.EVP_PKEY_CTX_set_rsa_padding((*C.EVP_PKEY_CTX)(ctx), C.int(pad)) == 1
}

// EVP_PKEY_CTX_set_rsa_pss_saltlen 设置 RSA-PSS 盐长。
func EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx unsafe.Pointer, saltlen int) bool {
	return C.EVP_PKEY_CTX_set_rsa_pss_saltlen((*C.EVP_PKEY_CTX)(ctx), C.int(saltlen)) == 1
}

// EVP_PKEY_CTX_set_rsa_mgf1_md 设置 RSA MGF1 摘要。
func EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md unsafe.Pointer) bool {
	return C.EVP_PKEY_CTX_set_rsa_mgf1_md((*C.EVP_PKEY_CTX)(ctx), (*C.EVP_MD)(md)) == 1
}

// EVP_PKEY_CTX_set_rsa_oaep_md 设置 RSA-OAEP 摘要。
func EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md unsafe.Pointer) bool {
	return C.EVP_PKEY_CTX_set_rsa_oaep_md((*C.EVP_PKEY_CTX)(ctx), (*C.EVP_MD)(md)) == 1
}

// I2d_PrivateKey 将私钥编码为传统 DER（RSA 为 PKCS#1）。
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
