// Package mac 提供消息认证码（MAC）的统一入口。
//
// 本版覆盖 HMAC（SM3 / MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512）、
// CMAC、GMAC、KMAC-128、KMAC-256、SipHash、Poly1305 与铜锁独有的 EIA3。
// 全部算法都经 provider 的 EVP_MAC_* 路径实现，按名入口 New / Sum /
// SumReader 与类型化的 CMAC / GMAC / KMAC128 / KMAC256 / SipHash /
// Poly1305 / EIA3 便捷入口并存。
//
// 签名与验签**不属本包**——见 asym。
//
// 安全提示：基于 MD5 / SHA-1 的 HMAC 仅保留兼容用途；新协议请用 SHA-256、
// SHA-384、SHA-512、SM3 等强摘要。CMAC / GMAC 的安全性还取决于底层分组
// 算法与 IV（GMAC 的 IV 必须与加密侧一致且不可复用）。
//
// Package mac provides a unified entry point for Message Authentication
// Codes (MAC).
//
// This version covers HMAC (SM3 / MD5 / SHA-1 / SHA-224 / SHA-256 /
// SHA-384 / SHA-512), CMAC, GMAC, KMAC-128, KMAC-256, SipHash, Poly1305
// and the Tongsuo-specific EIA3. Every algorithm is implemented through
// the provider EVP_MAC_* path; the by-name entries New / Sum /
// SumReader coexist with the typed CMAC / GMAC / KMAC128 / KMAC256 /
// SipHash / Poly1305 / EIA3 helpers.
//
// Signing and verification are NOT provided here — see the asym package.
//
// Security note: HMAC based on MD5 or SHA-1 is exported for
// compatibility only; prefer SHA-256, SHA-384, SHA-512 or SM3 for new
// protocols. The security of CMAC / GMAC also depends on the underlying
// block cipher and on the IV (the GMAC IV MUST match the encrypting side
// and MUST NOT be reused).
package mac
