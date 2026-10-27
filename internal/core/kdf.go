package core

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// HKDF 使用 HKDF（RFC 5869，extract-and-expand）从 secret 派生 length 字节。
// mdName 为摘要算法名（如 "SHA256"、"SHA1"、"SM3"）；secret 不能为空；
// salt/info 可为空。失败时返回包装了 OpError 的错误。
//
// HKDF derives length bytes from secret using HKDF (RFC 5869,
// extract-and-expand). mdName is the message-digest name (for example
// "SHA256", "SHA1" or "SM3"); secret must be non-empty; salt and info may be
// empty. On failure it returns an error wrapping an OpError.
func HKDF(mdName string, secret, salt, info []byte, length int) ([]byte, error) {
	if mdName == "" {
		return nil, fmt.Errorf("kdf: empty digest name")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("kdf: empty HKDF secret")
	}
	if length <= 0 {
		return nil, fmt.Errorf("kdf: invalid output length %d", length)
	}
	out := make([]byte, length)
	if !native.EVP_KDF_HKDF(mdName, 0 /* extract-and-expand */, secret, salt, info, out) {
		return nil, NewOpError("kdf: HKDF", native.PopError())
	}
	return out, nil
}

// PBKDF2 使用 PBKDF2（RFC 8018）从口令派生 keyLen 字节。
// mdName 为摘要算法名（如 "SHA1"、"SHA256"）；iter 为迭代次数（>=1）。
// password 不能为空。失败时返回包装了 OpError 的错误。
//
// PBKDF2 derives keyLen bytes from a password using PBKDF2 (RFC 8018).
// mdName is the message-digest name (for example "SHA1" or "SHA256"); iter is
// the iteration count (>= 1); password must be non-empty. On failure it
// returns an error wrapping an OpError.
func PBKDF2(mdName string, password, salt []byte, iter, keyLen int) ([]byte, error) {
	if mdName == "" {
		return nil, fmt.Errorf("kdf: empty digest name")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("kdf: empty password")
	}
	if iter < 1 {
		return nil, fmt.Errorf("kdf: invalid iteration count %d", iter)
	}
	if keyLen <= 0 {
		return nil, fmt.Errorf("kdf: invalid key length %d", keyLen)
	}
	out := make([]byte, keyLen)
	if !native.EVP_KDF_PBKDF2(mdName, password, salt, iter, out) {
		return nil, NewOpError("kdf: PBKDF2", native.PopError())
	}
	return out, nil
}

// Argon2IDAvailable 报告当前 Tongsuo 构建是否提供 ARGON2ID KDF。
// Argon2id 需要 OpenSSL 3.2+ 且编译含对应 provider；本库当前构建通常不可用。
//
// Argon2IDAvailable reports whether the current Tongsuo build provides the
// ARGON2ID KDF. Argon2id requires OpenSSL 3.2+ with the provider compiled in;
// the current build of this library usually does not provide it.
func Argon2IDAvailable() bool {
	return native.EVP_KDF_Available("ARGON2ID")
}

// KDFParams 是泛化 KDF 派生的参数包（核心层形态）。
// 各算法只取用其中一部分字段；未取用的字段被忽略。字段语义与 provider 的
// OSSL_PARAM 一一对应，由 Derive 转换为绑定层结构。
//
// KDFParams carries the parameters of a generic KDF derivation at the
// core layer. Each algorithm consumes a subset of the fields; the rest
// are ignored. The fields map one-to-one onto the provider OSSL_PARAM
// names and Derive converts them to the binding-layer struct.
type KDFParams struct {
	// Digest 是摘要算法名（多数 KDF 使用）。
	//
	// Digest is the message-digest name (used by most KDFs).
	Digest string
	// Mode 是模式字符串（HKDF / TLS13-KDF：EXTRACT_ONLY / EXPAND_ONLY；
	// KBKDF：COUNTER / FEEDBACK）。
	//
	// Mode is the mode string (HKDF / TLS13-KDF: EXTRACT_ONLY /
	// EXPAND_ONLY; KBKDF: COUNTER / FEEDBACK).
	Mode string
	// CEKAlg 是目标 CEK 算法名（X942KDF-ASN1）。
	//
	// CEKAlg names the target content-encryption key algorithm
	// (X942KDF-ASN1).
	CEKAlg string
	// MAC 是底层 MAC 实现名（KBKDF）。
	//
	// MAC names the underlying MAC implementation (KBKDF).
	MAC string
	// Key 是密钥材料（HKDF / TLS13-KDF / KBKDF / SSKDF / X942KDF / X963KDF）。
	//
	// Key is the keying material.
	Key []byte
	// Secret 是共享秘密 Z（SSKDF / TLS1-PRF / X942KDF / X963KDF 与 Key 同源）。
	//
	// Secret is the shared secret Z (SSKDF / TLS1-PRF / X942KDF /
	// X963KDF; it shares its source with Key).
	Secret []byte
	// Salt 是盐（HKDF / PBKDF2 / SCRYPT / SSKDF；KBKDF 下作为 label）。
	//
	// Salt is the salt (HKDF / PBKDF2 / SCRYPT / SSKDF; used as the
	// label by KBKDF).
	Salt []byte
	// Info 是上下文字节。
	//
	// Info is the context bytes.
	Info []byte
	// Pass 是口令（PBKDF2 / SCRYPT）。
	//
	// Pass is the password (PBKDF2 / SCRYPT).
	Pass []byte
	// Seed 是种子（TLS1-PRF）。
	//
	// Seed is the seed (TLS1-PRF).
	Seed []byte
	// Label / Prefix / Data 是 TLS13-KDF 的标签、前缀与 transcript 摘要。
	//
	// Label / Prefix / Data are the TLS13-KDF label, prefix and
	// transcript digest.
	Label  []byte
	Prefix []byte
	Data   []byte
	// UKM 是用户密钥材料（X942KDF-ASN1）。
	//
	// UKM is the user keying material (X942KDF-ASN1).
	UKM []byte
	// Entropy / Nonce 是 HMAC-DRBG-KDF 的熵输入与 nonce。
	//
	// Entropy / Nonce are the HMAC-DRBG-KDF entropy input and nonce.
	Entropy []byte
	Nonce   []byte
	// Iter 是 PBKDF2 的迭代次数。
	//
	// Iter is the PBKDF2 iteration count.
	Iter uint64
	// N / R / P / MaxMem 是 scrypt 成本参数；KBKDF 复用 R。
	//
	// N / R / P / MaxMem are the scrypt cost parameters; KBKDF reuses R.
	N      uint64
	R      uint64
	P      uint64
	MaxMem uint64
	// UseL / UseSeparator 选择 KBKDF 变体。
	//
	// UseL / UseSeparator select the KBKDF variant.
	UseL         bool
	UseSeparator bool
	// UseKeyBits 表示 X942KDF 用密钥比特长度替代 supp-pubinfo。
	//
	// UseKeyBits replaces supp-pubinfo with the key length in bits for
	// X942KDF.
	UseKeyBits bool
}

// Derive 按 provider 侧算法名执行一次性 KDF 派生。
// alg 为 provider 规范名（如 "HKDF"、"PBKDF2"、"SCRYPT"、"SSKDF"、"TLS1-PRF"、
// "TLS13-KDF"、"KBKDF"、"X942KDF-ASN1"、"X963KDF"、"HMAC-DRBG-KDF"）。
// p 为参数包（可为 nil，表示全部取默认）；out 缓冲区长度即期望的派生长度。
// 失败时返回包装了 OpError 的错误。
//
// Derive performs a one-shot KDF derivation by provider-side algorithm
// name. alg is a provider canonical name (for example "HKDF", "PBKDF2",
// "SCRYPT", "SSKDF", "TLS1-PRF", "TLS13-KDF", "KBKDF", "X942KDF-ASN1",
// "X963KDF" or "HMAC-DRBG-KDF"). p carries the parameters and may be nil
// (meaning "use the defaults"); the length of out is the requested output
// length. On failure it returns an error wrapping an OpError.
func Derive(alg string, p *KDFParams, out []byte) error {
	if alg == "" {
		return fmt.Errorf("kdf: empty algorithm name")
	}
	if len(out) == 0 {
		return fmt.Errorf("kdf: invalid output length %d", len(out))
	}
	var np *native.KDFParams
	if p != nil {
		np = &native.KDFParams{
			Digest:       p.Digest,
			Mode:         p.Mode,
			CEKAlg:       p.CEKAlg,
			MAC:          p.MAC,
			Key:          p.Key,
			Secret:       p.Secret,
			Salt:         p.Salt,
			Info:         p.Info,
			Pass:         p.Pass,
			Seed:         p.Seed,
			Label:        p.Label,
			Entropy:      p.Entropy,
			Nonce:        p.Nonce,
			UKM:          p.UKM,
			Prefix:       p.Prefix,
			Data:         p.Data,
			Iter:         p.Iter,
			N:            p.N,
			R:            p.R,
			P:            p.P,
			MaxMem:       p.MaxMem,
			UseL:         p.UseL,
			UseSeparator: p.UseSeparator,
			UseKeyBits:   p.UseKeyBits,
		}
	}
	if !native.EVP_KDF_Derive(alg, np, out) {
		return NewOpError("kdf: "+alg, native.PopError())
	}
	return nil
}
