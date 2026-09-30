// Package sym 汇总对称加密与对称密钥对象（crypto/aes + crypto/sm4 + key 的
// 对称部分），覆盖 AES-128 / AES-256 与 SM4 的 ECB / CBC / CTR / OFB / CFB /
// GCM 等模式。CLI 入口对应 `tongsuo enc -<name>`。
//
// 安全提示：
//   - ECB 无扩散语义，禁止用于多块数据；本版保留仅为兼容既有格式。
//   - CTR/OFB/CFB 为流式模式，同一密钥下 nonce/IV 必须唯一，否则破坏机密性。
//   - GCM 是 AEAD，nonce 唯一性是机密性与认证性的前提。
//
// 包内 ECB / CBC 一次性入口均使用 PKCS#7 填充；无填充的 ECBZero / CBCZero
// 仅供遗留数据使用。NewCipher 返回的 cipher.Block 实现并发安全（内部
// EVP_CIPHER_CTX_copy 模板副本，与 stdlib 一致）。
//
// Package sym collects symmetric cipher operations and symmetric key
// objects (the former crypto/aes + crypto/sm4 + key's symmetric bits),
// covering ECB / CBC / CTR / OFB / CFB / GCM modes for AES-128 / AES-256
// and SM4. The CLI shape mirrors `tongsuo enc -<name>`.
//
// Security notes:
//   - ECB has no diffusion; do not use it for new protocols with
//     multi-block data. The ECB helpers are kept for compatibility only.
//   - CTR/OFB/CFB are stream modes; under a fixed key the nonce/IV must
//     be unique per message or confidentiality breaks.
//   - GCM is AEAD; nonce uniqueness is required for both confidentiality
//     and authenticity.
//
// The ECB / CBC one-shot helpers use PKCS#7 padding; padding-less
// ECBZero / CBCZero are for legacy data. cipher.Block instances returned
// by NewCipher are safe for concurrent use (EVP_CIPHER_CTX_copy template
// pattern, matching stdlib).
package sym
