package asym

// Algorithm 表示非对称算法标识。
// 本枚举覆盖铜锁 EVP_PKEY 算法族；Algorithm 字符串大小写不敏感（按名分发时做 ToUpper）。
//
// Algorithm identifies an asymmetric algorithm. The constants enumerate the
// algorithm families supported by Tongsuo's EVP_PKEY layer; algorithm
// names are case-insensitive in name-based dispatch (callers should use
// the canonical Alg* constants or pass them through ToUpper first).
type Algorithm string

// Algorithm 常量集合。
//
// Algorithm constants.
const (
	AlgSM2     Algorithm = "SM2"     // 国密 SM2（sm2p256v1 曲线，SM2withSM3 签名）
	AlgRSA     Algorithm = "RSA"     // RSA（PKCS#1 v1.5 / PSS / OAEP）
	AlgEC      Algorithm = "EC"      // 通用 ECDSA（曲线名通过 ECOptions.Curve 选）
	AlgEd25519 Algorithm = "ED25519" // Ed25519（RFC 8032）
	AlgEd448   Algorithm = "ED448"   // Ed448（RFC 8032）
	AlgX25519  Algorithm = "X25519"  // X25519（RFC 7748，密钥生成；协商留 ecdh）
	AlgX448    Algorithm = "X448"    // X448（RFC 7748，密钥生成；协商留 ecdh）
)

// String 返回算法名（大写形式）。
//
// String returns the algorithm name in canonical upper case.
func (a Algorithm) String() string { return string(a) }

// SM2withSM3 是 SM2 默认签名算法（GB/T 32918.2-2016）。
// 对应铜锁 EVP_sm3() + SM2 provider；对外签名值是 ASN.1 DER 格式。
//
// SM2withSM3 is the default SM2 signature algorithm (GB/T 32918.2-2016).
// It maps to Tongsuo's EVP_sm3() + SM2 provider; the returned signature
// is in ASN.1 DER format.
const SM2withSM3 = "SM2withSM3"

// DefaultSM2ID 是 SM2 默认用户标识符（GM/T 0003-2012 规定值）。
// Sign / Verify 传 id=nil 时回退到本值；如需自定义请使用 SignWithID / VerifyWithID。
//
// DefaultSM2ID is the default SM2 user identifier per GM/T 0003-2012.
// Pass id=nil to Sign / Verify to use this value; for custom identifiers
// use SignWithID / VerifyWithID.
var DefaultSM2ID = []byte("1234567812345678")

// DefaultID 是 DefaultSM2ID 的语义别名；保留与既有教程/示例一致的命名。
//
// DefaultID is a semantic alias of DefaultSM2ID; it preserves the
// naming familiar from existing tutorials and examples.
var DefaultID = DefaultSM2ID

// SM2 密文格式常量（GB/T 32918.4-2016）。
//
// SM2 ciphertext format constants (GB/T 32918.4-2016). These are kept
// private because they only matter to Format / EncryptWithOrder /
// DecryptWithOrder.
const (
	sm2CoordBytes        = 32   // 单坐标字节长度
	sm2C1UncompressedLen = 65   // 未压缩 C1 点（0x04 前缀 + X + Y）
	sm2C1CompressedLen   = 33   // 压缩 C1 点（0x02/0x03 前缀 + X）
	sm2C1PrefixUncomp    = 0x04 // 未压缩点前缀
	sm2C1PrefixCompEven  = 0x02 // 压缩点偶数 Y 前缀
	sm2C1PrefixCompOdd   = 0x03 // 压缩点奇数 Y 前缀
)
