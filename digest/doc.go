// Package digest 汇总铜锁支持的摘要（哈希）算法，提供按算法名分发的统一入口
// （New / Sum / SumReader）与按算法命名的类型化入口（NewSM3 / SumSHA256 等）。
//
// 本包合并原 crypto/{sm3,md5,sha1,sha256,sha512} 五个包，并补齐 SHA-224 与
// SHA-384；保留 Go 惯例接口 hash.Hash 以便与标准库及生态组合使用。
//
// 安全提示：MD5 与 SHA-1 已不适用于数字签名，仅可用于兼容既有格式与完整性校验。
//
// Package digest collects the message-digest algorithms supported by
// Tongsuo and exposes two entry styles: a by-name dispatch (New / Sum /
// SumReader) and algorithm-named typed entries (NewSM3 / SumSHA256, …).
//
// The package merges the former crypto/{sm3,md5,sha1,sha256,sha512}
// packages and adds SHA-224 and SHA-384. It keeps the idiomatic
// hash.Hash interface so callers can compose it with the standard
// library and the wider ecosystem.
//
// Security note: MD5 and SHA-1 are no longer suitable for digital
// signatures; use them only for compatibility with legacy formats and
// for integrity checks.
package digest
