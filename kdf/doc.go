// Package kdf 汇总密钥派生函数（KDF），覆盖 RFC 5869 HKDF、RFC 8018 PBKDF2、
// 与 Argon2id（依赖铜锁 provider）。按名分发的 Derive 入口与 CLI 的
// `openssl kdf <ALG> -kdfopt …` 对应。
//
// 本版保留 legacy 强类型 HKDF/PBKDF2/Argon2ID 入口，与按名入口并存；
// SCrypt / SSKDF / TLS1-PRF / KBKDF 等 10 种其余算法在 0.4.0 后补齐
// （需新增 EVP_KDF_fetch 泛化绑定）。
//
// Package kdf collects key-derivation functions: RFC 5869 HKDF,
// RFC 8018 PBKDF2 and Argon2id (provider-dependent). The by-name Derive
// entry mirrors the Tongsuo CLI's `openssl kdf <ALG> -kdfopt …` form.
//
// The legacy typed HKDF / PBKDF2 / Argon2ID helpers are kept alongside
// the by-name entry; SCrypt, SSKDF, TLS1-PRF, KBKDF and others will be
// added in 0.4.0 once the EVP_KDF_fetch binding is generalised.
package kdf
