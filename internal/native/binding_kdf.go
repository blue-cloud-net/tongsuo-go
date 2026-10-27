package native

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// bytesPtr 返回切片的底层指针;空切片返回 nil。
// bytesPtr returns a pointer to the slice's backing array, or nil for an
// empty slice.
func bytesPtr(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

// cstr 分配一个 NUL 结尾的 C 字符串副本,并返回释放函数。
// cstr allocates a NUL-terminated C copy of s and returns a release
// function; an empty string yields a nil pointer and a no-op release.
func cstr(s string) (*C.char, func()) {
	if s == "" {
		return nil, func() {}
	}
	c := C.CString(s)
	return c, func() { C.free(unsafe.Pointer(c)) }
}

// EVP_KDF_HKDF 执行一次性 HKDF（RFC 5869）派生。
// mode 取 EVP_KDF_HKDF_MODE_*（0=extract-and-expand）；digest 为摘要算法名
// （如 "SHA256"）。成功返回 true，失败返回 false（错误已入队列）。
// EVP_KDF_HKDF performs a one-shot HKDF (RFC 5869) derivation.
// mode is one of EVP_KDF_HKDF_MODE_* (0 = extract-and-expand); digest is the
// message-digest name (for example "SHA256"). It returns true on success and
// false on failure (the error is queued for ERR_get_error).
func EVP_KDF_HKDF(digest string, mode int, key, salt, info, out []byte) bool {
	cd, free := cstr(digest)
	defer free()
	return C.X_EVP_KDF_HKDF(cd, C.int(mode),
		bytesPtr(key), C.size_t(len(key)),
		bytesPtr(salt), C.size_t(len(salt)),
		bytesPtr(info), C.size_t(len(info)),
		bytesPtr(out), C.size_t(len(out))) == 1
}

// EVP_KDF_PBKDF2 执行一次性 PBKDF2（RFC 8018）派生。
// digest 为摘要算法名（如 "SHA1"、"SHA256"）；iter 为迭代次数。成功返回 true。
// EVP_KDF_PBKDF2 performs a one-shot PBKDF2 (RFC 8018) derivation.
// digest is the message-digest name (for example "SHA1" or "SHA256"); iter is
// the iteration count. It returns true on success.
func EVP_KDF_PBKDF2(digest string, pass, salt []byte, iter int, out []byte) bool {
	cd, free := cstr(digest)
	defer free()
	return C.X_EVP_KDF_PBKDF2(cd,
		bytesPtr(pass), C.size_t(len(pass)),
		bytesPtr(salt), C.size_t(len(salt)),
		C.int(iter),
		bytesPtr(out), C.size_t(len(out))) == 1
}

// EVP_KDF_Available 探测指定 KDF 算法是否可用（provider 是否加载）。
// 探测失败会清空队列中的错误,不影响后续错误读取。
// EVP_KDF_Available reports whether the named KDF algorithm is available
// (its provider is loaded). A failed probe clears the error queue so it does
// not disturb later error reads.
func EVP_KDF_Available(algorithm string) bool {
	ca, free := cstr(algorithm)
	defer free()
	return C.X_EVP_KDF_available(ca) == 1
}

// KDFParams 是泛化 KDF 派生的参数包。
// 各算法只取用其中一部分字段；未取用的字段被忽略。
//
// KDFParams carries the parameters of a generic KDF derivation. Each
// algorithm consumes a subset of the fields; the rest are ignored.
type KDFParams struct {
	// Digest 是摘要算法名（HKDF / PBKDF2 / SSKDF / TLS1-PRF / TLS13-KDF /
	// KBKDF / X942KDF / X963KDF / HMAC-DRBG-KDF 使用）。
	//
	// Digest selects the message-digest name.
	Digest string
	// Mode 是模式字符串（KBKDF："counter" / "feedback"）。
	//
	// Mode selects the KDF mode (KBKDF: "counter" / "feedback").
	Mode string
	// CEKAlg 是目标 CEK 算法名（X942KDF-ASN1 必填，如 "AES-128-CBC"）。
	//
	// CEKAlg names the target content-encryption key algorithm
	// (required by X942KDF-ASN1, for example "AES-128-CBC").
	CEKAlg string
	// MAC 是底层 MAC 实现名（KBKDF 必填，如 "HMAC" / "CMAC" / "KMAC-128"）。
	//
	// MAC names the underlying MAC implementation (required by KBKDF, for
	// example "HMAC", "CMAC" or "KMAC-128").
	MAC string
	// Key 是密钥材料。
	//
	// Key is the keying material.
	Key []byte
	// Secret 是共享秘密 Z。
	//
	// Secret is the shared secret Z.
	Secret []byte
	// Salt 是盐（KBKDF 下作为 label 使用）。
	//
	// Salt is the salt (used as the label by KBKDF).
	Salt []byte
	// Info 是上下文字节。
	//
	// Info is the context bytes.
	Info []byte
	// Pass 是口令。
	//
	// Pass is the password.
	Pass []byte
	// Seed 是种子（TLS1-PRF）。
	//
	// Seed is the seed (TLS1-PRF).
	Seed []byte
	// Label 是标签（TLS13-KDF）。
	//
	// Label is the label (TLS13-KDF).
	Label []byte
	// Entropy 是熵输入（HMAC-DRBG-KDF）。
	//
	// Entropy is the entropy input (HMAC-DRBG-KDF).
	Entropy []byte
	// Nonce 是 nonce（HMAC-DRBG-KDF）。
	//
	// Nonce is the nonce (HMAC-DRBG-KDF).
	Nonce []byte
	// UKM 是用户密钥材料（X942KDF-ASN1）。
	//
	// UKM is the user keying material (X942KDF-ASN1).
	UKM []byte
	// Prefix 是标签前缀（TLS13-KDF；标准值为 "tls13 "）。
	//
	// Prefix is the label prefix (TLS13-KDF; the standard value is "tls13 ").
	Prefix []byte
	// Data 是上下文字节（TLS13-KDF 的 Expand 步作为 transcript 摘要）。
	//
	// Data is the context bytes (the transcript digest in the TLS13-KDF
	// expand step).
	Data []byte
	// Iter 是迭代次数（PBKDF2）。
	//
	// Iter is the iteration count (PBKDF2).
	Iter uint64
	// N / R / P 是 scrypt 成本参数。
	//
	// N / R / P are the scrypt cost parameters.
	N uint64
	R uint64
	P uint64
	// MaxMem 是 scrypt 内存上限（字节）。
	//
	// MaxMem is the scrypt memory limit in bytes.
	MaxMem uint64
	// UseL 表示 KBKDF 是否在末尾附加 key 的比特长度。
	//
	// UseL appends the key length in bits to the KBKDF output.
	UseL bool
	// UseSeparator 表示 KBKDF 是否使用 separator 变体。
	//
	// UseSeparator selects the separator variant of KBKDF.
	UseSeparator bool
	// UseKeyBits 表示 X942KDF 是否以 key 的比特长度替代 supp-pubinfo。
	//
	// UseKeyBits replaces supp-pubinfo with the key length in bits for
	// X942KDF.
	UseKeyBits bool
}

// EVP_KDF_Derive 按算法名执行一次性 KDF 派生。
// algorithm 为 provider 侧的算法名（如 "HKDF"、"SCRYPT"、"TLS13-KDF"）。
// out 缓冲区长度即期望的派生长度。成功返回 true，失败返回 false（错误已入队列）。
//
// EVP_KDF_Derive performs a one-shot KDF derivation by algorithm name.
// algorithm is the provider-side name (for example "HKDF", "SCRYPT" or
// "TLS13-KDF"). The length of out is the requested output length. It returns
// true on success and false on failure (the error is queued).
func EVP_KDF_Derive(algorithm string, p *KDFParams, out []byte) bool {
	calg, freeAlg := cstr(algorithm)
	defer freeAlg()
	if p == nil {
		p = &KDFParams{}
	}
	cdigest, freeDigest := cstr(p.Digest)
	defer freeDigest()
	cmode, freeMode := cstr(p.Mode)
	defer freeMode()
	ccek, freeCEK := cstr(p.CEKAlg)
	defer freeCEK()
	cmac, freeMAC := cstr(p.MAC)
	defer freeMAC()

	// 参数结构体里要存放字节序列的指针，而 Go 不允许把 Go 指针存进
	// 传给 C 的结构体（cgo 会拒绝 "Go pointer to unpinned Go pointer"）。
	// 因此这里把每个字节字段复制到 C 堆内存，再把 C 指针填进结构体。
	keyPtr, freeKey := cbytes(p.Key)
	defer freeKey()
	secretPtr, freeSecret := cbytes(p.Secret)
	defer freeSecret()
	saltPtr, freeSalt := cbytes(p.Salt)
	defer freeSalt()
	infoPtr, freeInfo := cbytes(p.Info)
	defer freeInfo()
	passPtr, freePass := cbytes(p.Pass)
	defer freePass()
	seedPtr, freeSeed := cbytes(p.Seed)
	defer freeSeed()
	labelPtr, freeLabel := cbytes(p.Label)
	defer freeLabel()
	entropyPtr, freeEntropy := cbytes(p.Entropy)
	defer freeEntropy()
	noncePtr, freeNonce := cbytes(p.Nonce)
	defer freeNonce()
	ukmPtr, freeUKM := cbytes(p.UKM)
	defer freeUKM()
	prefixPtr, freePrefix := cbytes(p.Prefix)
	defer freePrefix()
	dataPtr, freeData := cbytes(p.Data)
	defer freeData()

	var params C.X_KDF_PARAMS
	params.digest = cdigest
	params.mode = cmode
	params.cekalg = ccek
	params.mac = cmac
	params.key = (*C.uchar)(keyPtr)
	params.keylen = C.size_t(len(p.Key))
	params.secret = (*C.uchar)(secretPtr)
	params.secretlen = C.size_t(len(p.Secret))
	params.salt = (*C.uchar)(saltPtr)
	params.saltlen = C.size_t(len(p.Salt))
	params.info = (*C.uchar)(infoPtr)
	params.infolen = C.size_t(len(p.Info))
	params.pass = (*C.uchar)(passPtr)
	params.passlen = C.size_t(len(p.Pass))
	params.seed = (*C.uchar)(seedPtr)
	params.seedlen = C.size_t(len(p.Seed))
	params.label = (*C.uchar)(labelPtr)
	params.labellen = C.size_t(len(p.Label))
	params.entropy = (*C.uchar)(entropyPtr)
	params.entropylen = C.size_t(len(p.Entropy))
	params.nonce = (*C.uchar)(noncePtr)
	params.noncelen = C.size_t(len(p.Nonce))
	params.ukm = (*C.uchar)(ukmPtr)
	params.ukmlen = C.size_t(len(p.UKM))
	params.prefix = (*C.uchar)(prefixPtr)
	params.prefixlen = C.size_t(len(p.Prefix))
	params.data = (*C.uchar)(dataPtr)
	params.datalen = C.size_t(len(p.Data))
	params.iter = C.uint64_t(p.Iter)
	params.n = C.uint64_t(p.N)
	params.r = C.uint64_t(p.R)
	params.p = C.uint64_t(p.P)
	params.maxmem = C.uint64_t(p.MaxMem)
	params.use_l = C.int(boolToInt(p.UseL))
	params.use_separator = C.int(boolToInt(p.UseSeparator))
	params.use_keybits = C.int(boolToInt(p.UseKeyBits))

	return C.X_EVP_KDF_derive(calg, &params, bytesPtr(out), C.size_t(len(out))) == 1
}

// cbytes 把 b 复制到 C 堆内存，返回指针与释放函数。
// 空切片返回 nil 指针与 no-op 释放函数（与 bytesPtr 的空值语义一致）。
//
// cbytes copies b into C heap memory and returns the pointer together with
// its release function. An empty slice yields a nil pointer and a no-op
// release function, matching the empty-value semantics of bytesPtr.
func cbytes(b []byte) (unsafe.Pointer, func()) {
	if len(b) == 0 {
		return nil, func() {}
	}
	p := C.CBytes(b)
	return p, func() { C.free(p) }
}

// boolToInt 把 Go 的 bool 转成 C 的 int（0/1）。
//
// boolToInt converts a Go bool into a C int (0 or 1).
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// EVP_KDF_KBKDFRSupported 报告本构建的 KBKDF 是否接受 r（计数器宽度）参数。
// 该参数名 OSSL_KDF_PARAM_KBKDF_R 仅存在于 OpenSSL 3.2+。
//
// EVP_KDF_KBKDFRSupported reports whether this build's KBKDF accepts the
// r (counter width) parameter. The parameter name
// OSSL_KDF_PARAM_KBKDF_R only exists in OpenSSL 3.2+.
func EVP_KDF_KBKDFRSupported() bool { return C.X_EVP_KDF_kbkdf_r_supported() == 1 }
