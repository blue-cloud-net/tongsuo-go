// Package mac 提供消息认证码（MAC）的统一入口。
//
// 本版覆盖 HMAC（SM3 / MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512）。
// CMAC / GMAC / KMAC / SipHash / Poly1305 / EIA3 计划在 0.4.0 版本提供，
// 需新增 EVP_MAC_* 系列 cgo 绑定。
//
// 签名与验签**不属本包**——见 asym。
//
// 安全提示：基于 MD5 / SHA-1 的 HMAC 仅保留兼容用途；新协议请用 SHA-256、
// SHA-384、SHA-512、SM3 等强摘要。
//
// Package mac provides a unified entry point for Message Authentication
// Codes (MAC). This version covers HMAC (SM3 / MD5 / SHA-1 / SHA-224 /
// SHA-256 / SHA-384 / SHA-512). CMAC / GMAC / KMAC / SipHash / Poly1305 /
// EIA3 are scheduled for 0.4.0 and require new EVP_MAC_* cgo bindings.
//
// Signing and verification are NOT provided here — see the asym package.
//
// Security note: HMAC based on MD5 or SHA-1 is exported for
// compatibility only; prefer SHA-256, SHA-384, SHA-512 or SM3 for new
// protocols.
package mac
