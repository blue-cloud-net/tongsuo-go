// Package sym 汇总对称加密与对称密钥对象（crypto/aes + crypto/sm4 + key 的
// 对称部分），覆盖 AES-128 / AES-192 / AES-256 与 SM4 的 ECB / CBC / CTR /
// OFB / CFB / GCM / CCM / XTS 等模式，以及 ChaCha20 与
// ChaCha20-Poly1305。CLI 入口对应 `tongsuo enc -<name>`。
//
// 安全提示：
//   - ECB 无扩散语义，禁止用于多块数据；本版保留仅为兼容既有格式。
//   - CTR/OFB/CFB/ChaCha20 为流式模式，同一密钥下 nonce/IV 必须唯一，
//     否则破坏机密性。
//   - GCM / CCM / ChaCha20-Poly1305 是 AEAD，nonce 唯一性是机密性与认证性
//     的前提。
//   - XTS 是**无认证**的磁盘加密模式：同一分量密钥对下严禁加密两条长度相同
//     的数据（会泄漏明文异或）。
//
// 包内 ECB / CBC 一次性入口均使用 PKCS#7 填充；无填充的 ECBZero / CBCZero
// 仅供遗留数据使用。NewCipher 返回的 cipher.Block 实现并发安全（内部
// EVP_CIPHER_CTX_copy 模板副本，与 stdlib 一致）；NewAEAD 返回的 cipher.AEAD
// 覆盖 GCM / CCM / ChaCha20-Poly1305。
//
// Package sym collects symmetric cipher operations and symmetric key
// objects (the former crypto/aes + crypto/sm4 + key's symmetric bits),
// covering ECB / CBC / CTR / OFB / CFB / GCM / CCM / XTS modes for
// AES-128 / AES-192 / AES-256 and SM4, plus ChaCha20 and
// ChaCha20-Poly1305. The CLI shape mirrors `tongsuo enc -<name>`.
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
//
// The ECB / CBC one-shot helpers use PKCS#7 padding; padding-less
// ECBZero / CBCZero are for legacy data. cipher.Block instances returned
// by NewCipher are safe for concurrent use (EVP_CIPHER_CTX_copy template
// pattern, matching stdlib); cipher.AEAD instances returned by NewAEAD
// cover GCM / CCM / ChaCha20-Poly1305.
package sym
