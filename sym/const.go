package sym

// 对称加密通用常量。所有分组算法（AES-128 / AES-192 / AES-256 / SM4）共用
// 同一 16 字节分组；AEAD 模式（GCM / CCM / ChaCha20-Poly1305）共用
// 12 字节推荐 nonce 与 16 字节标签长度。
//
// Common symmetric cipher constants. All block algorithms (AES-128 /
// AES-192 / AES-256 / SM4) share the same 16-byte block; the AEAD modes
// (GCM / CCM / ChaCha20-Poly1305) share the 12-byte recommended nonce and
// the 16-byte tag length.
const (
	// BlockSize 为分组长度（字节）；AES 与 SM4 同为 16。
	//
	// BlockSize is the symmetric block size in bytes (16 for both AES
	// and SM4).
	BlockSize = 16
	// NonceSize 为 AEAD 推荐 Nonce 长度（96 位 / 12 字节）。
	//
	// NonceSize is the recommended AEAD nonce length in bytes (96 bits).
	NonceSize = 12
	// TagSize 为 AEAD 认证标签长度（128 位 / 16 字节）。
	//
	// TagSize is the AEAD authentication tag length in bytes (128 bits).
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
	// AES192KeySize 为 AES-192 密钥长度（24 字节）。
	//
	// AES192KeySize is the AES-192 key length in bytes.
	AES192KeySize = 24
	// AES256KeySize 为 AES-256 密钥长度（32 字节）。
	//
	// AES256KeySize is the AES-256 key length in bytes.
	AES256KeySize = 32
	// SM4KeySize 为 SM4 密钥长度（16 字节）。
	//
	// SM4KeySize is the SM4 key length in bytes.
	SM4KeySize = 16
	// SM4XTSKeySize 为 SM4-XTS 密钥长度（32 字节，两个 16 字节分量密钥）。
	//
	// SM4XTSKeySize is the SM4-XTS key length in bytes (two 16-byte
	// component keys).
	SM4XTSKeySize = 32
	// ChaCha20KeySize 为 ChaCha20 / ChaCha20-Poly1305 密钥长度（32 字节）。
	//
	// ChaCha20KeySize is the ChaCha20 / ChaCha20-Poly1305 key length in
	// bytes.
	ChaCha20KeySize = 32
	// ChaCha20IVSize 为 ChaCha20 流模式的 IV 长度（16 字节：4 字节计数器 + 12 字节 nonce）。
	//
	// ChaCha20IVSize is the ChaCha20 stream-mode IV length in bytes (a
	// 4-byte counter followed by a 12-byte nonce).
	ChaCha20IVSize = 16
	// SM4CCMNonceSize 为 SM4-CCM 的推荐 nonce 长度（12 字节）；
	// CCM 允许 7..13 字节。
	//
	// SM4CCMNonceSize is the recommended SM4-CCM nonce length in bytes (12);
	// CCM accepts 7 to 13 bytes.
	SM4CCMNonceSize = 12
)
