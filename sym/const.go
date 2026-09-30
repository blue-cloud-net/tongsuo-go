package sym

// 对称加密通用常量。所有对称算法（AES-128 / AES-256 / SM4）共用同一
// 16 字节分组与 12/16 字节 GCM nonce/tag 推荐长度。
//
// Common symmetric cipher constants. All algorithms (AES-128 / AES-256
// / SM4) share the same 16-byte block and 12/16-byte GCM nonce/tag
// recommendations.
const (
	// BlockSize 为分组长度（字节）；AES 与 SM4 同为 16。
	//
	// BlockSize is the symmetric block size in bytes (16 for both AES
	// and SM4).
	BlockSize = 16
	// NonceSize 为 GCM 推荐 Nonce 长度（96 位 / 12 字节）。
	//
	// NonceSize is the recommended GCM nonce length in bytes (96 bits).
	NonceSize = 12
	// TagSize 为 GCM 认证标签长度（128 位 / 16 字节）。
	//
	// TagSize is the GCM authentication tag length in bytes (128 bits).
	TagSize = 16
)

// 各算法的密钥长度（字节）。
//
// Per-algorithm key sizes in bytes.
const (
	// AES128KeySize 为 AES-128 密钥长度（16 字节）。
	//
	// AES128KeySize is the AES-128 key length in bytes.
	AES128KeySize = 16
	// AES256KeySize 为 AES-256 密钥长度（32 字节）。
	//
	// AES256KeySize is the AES-256 key length in bytes.
	AES256KeySize = 32
	// SM4KeySize 为 SM4 密钥长度（16 字节）。
	//
	// SM4KeySize is the SM4 key length in bytes.
	SM4KeySize = 16
)
