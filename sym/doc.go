// Package sym 汇总对称加密与对称密钥对象（crypto/aes + crypto/sm4 + key 的
// 对称部分），覆盖 AES-128 / AES-192 / AES-256 与 SM4 的 ECB / CBC / CTR /
// OFB / CFB / GCM / CCM / XTS 等模式，DES / DES-EDE（2 密钥）/ DES-EDE3 的
// ECB / CBC，以及 ChaCha20 与 ChaCha20-Poly1305。CLI 入口对应
// `tongsuo enc -<name>`。
//
// 填充矩阵：按算法名分发的 Encrypt / Decrypt 接受 Options.Padding，取值为
// "pkcs7"（默认）/ "zero" / "none"。合法组合可用 Supports / Paddings 静态
// 查询，无需先提交数据：
//
//   - 分组模式（AES / SM4 / DES 家族的 ECB 与 CBC）：pkcs7、zero、none；
//   - 流模式（CTR / OFB / CFB）与 ChaCha20、SM4-XTS：仅 none（空串等价）；
//   - AEAD（GCM / CCM / ChaCha20-Poly1305）：不经过填充层，请用 EncryptAEAD。
//
// 非法组合（含未知填充名）返回 ErrUnsupportedPadding。zero 表示「加密时补零到
// 分组整数倍、解密不剥离」，需要精确明文长度时由调用方按已知长度截断；none
// 要求输入长度本身就是分组整数倍。
//
// 安全提示：
//   - ECB 无扩散语义，禁止用于多块数据；本版保留仅为兼容既有格式。
//   - CTR/OFB/CFB/ChaCha20 为流式模式，同一密钥下 nonce/IV 必须唯一，
//     否则破坏机密性。
//   - GCM / CCM / ChaCha20-Poly1305 是 AEAD，nonce 唯一性是机密性与认证性
//     的前提。
//   - XTS 是**无认证**的磁盘加密模式：同一分量密钥对下严禁加密两条长度相同
//     的数据（会泄漏明文异或）。
//   - DES 家族（DES / DES-EDE / DES-EDE3）**仅用于兼容既有数据**：单 DES 只有
//     56 位有效密钥，已可被穷举；2 密钥 3DES 约 80 位。单 DES 在铜锁中只注册于
//     legacy provider，本库不加载 legacy，而是以 K‖K‖K（三份相同密钥）驱动
//     DES-EDE3 实现，输出与单 DES 逐字节相同。
//
// 包内 ECB / CBC 一次性入口均使用 PKCS#7 填充；Zero 变体使用零填充。NewCipher
// 返回的 cipher.Block 实现并发安全（内部 EVP_CIPHER_CTX_copy 模板副本，与
// stdlib 一致）；NewAEAD 返回的 cipher.AEAD 覆盖 GCM / CCM /
// ChaCha20-Poly1305。
//
// Package sym collects symmetric cipher operations and symmetric key
// objects (the former crypto/aes + crypto/sm4 + key's symmetric bits),
// covering ECB / CBC / CTR / OFB / CFB / GCM / CCM / XTS modes for
// AES-128 / AES-192 / AES-256 and SM4, ECB / CBC for DES / DES-EDE
// (two-key) / DES-EDE3, plus ChaCha20 and ChaCha20-Poly1305. The CLI shape
// mirrors `tongsuo enc -<name>`.
//
// Padding matrix: the by-name Encrypt / Decrypt accept Options.Padding
// with "pkcs7" (default) / "zero" / "none". Valid combinations can be
// queried statically through Supports / Paddings, without submitting any
// data:
//
//   - block modes (ECB and CBC of the AES / SM4 / DES families): pkcs7,
//     zero, none;
//   - stream modes (CTR / OFB / CFB), ChaCha20 and SM4-XTS: none only (the
//     empty string is equivalent);
//   - AEAD (GCM / CCM / ChaCha20-Poly1305): never reaches the padding
//     layer; use EncryptAEAD instead.
//
// Invalid combinations (including unknown padding names) return
// ErrUnsupportedPadding. zero means "pad with 0x00 up to a block boundary
// on encryption, never strip on decryption" — callers needing the exact
// length must truncate using a known size; none requires the input to be
// block-aligned already.
//
// Security notes:
//   - ECB has no diffusion; do not use it for new protocols with
//     multi-block data. The ECB helpers are kept for compatibility only.
//   - CTR/OFB/CFB/ChaCha20 are stream modes; under a fixed key the
//     nonce/IV must be unique per message or confidentiality breaks.
//   - GCM / CCM / ChaCha20-Poly1305 are AEAD; nonce uniqueness is
//     required for both confidentiality and authenticity.
//   - XTS is an **unauthenticated** disk-encryption mode: never encrypt
//     two messages of the same length under the same component key (that
//     leaks the XOR of the plaintexts).
//   - The DES family (DES / DES-EDE / DES-EDE3) exists **for legacy data
//     only**: single DES has a 56-bit effective key and is brute-forceable,
//     two-key 3DES about 80 bits. Single DES is registered only in the
//     legacy provider of Tongsuo; this library never loads legacy and
//     instead drives DES-EDE3 with K‖K‖K (three identical subkeys), which
//     produces byte-identical output.
//
// The ECB / CBC one-shot helpers use PKCS#7 padding; the Zero variants use
// zero padding. cipher.Block instances returned by NewCipher are safe for
// concurrent use (EVP_CIPHER_CTX_copy template pattern, matching stdlib);
// cipher.AEAD instances returned by NewAEAD cover GCM / CCM /
// ChaCha20-Poly1305.
package sym
