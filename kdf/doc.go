// Package kdf 汇总密钥派生函数（KDF），覆盖 RFC 5869 HKDF、RFC 8018 PBKDF2、
// RFC 7914 scrypt、SP 800-56C 单步 KDF、TLS 1.0/1.1 PRF、TLS 1.3 KDF、
// SP 800-108 KBKDF、ANSI X9.42 / X9.63 KDF、SP 800-90A HMAC-DRBG，
// 以及依赖铜锁 provider 的 Argon2id。按名分发的 Derive 入口与 CLI 的
// `openssl kdf <ALG> -kdfopt …` 对应。
//
// 每种算法同时提供两条入口：类型化入口（如 Scrypt、TLS13KDFExtract）便于
// 直接调用并做参数校验；按名入口 Derive 接受 Options，字段语义与 provider 的
// OSSL_PARAM 一致，便于按运行时名称分发。
//
// Package kdf collects key-derivation functions: RFC 5869 HKDF, RFC 8018
// PBKDF2, RFC 7914 scrypt, the SP 800-56C single-step KDF, TLS 1.0/1.1
// PRF, TLS 1.3 KDF, SP 800-108 KBKDF, ANSI X9.42 / X9.63 KDF, SP 800-90A
// HMAC-DRBG and the provider-dependent Argon2id. The by-name Derive entry
// mirrors the Tongsuo CLI's `openssl kdf <ALG> -kdfopt …` form.
//
// Every algorithm exposes two entries: a typed helper (for example Scrypt
// or TLS13KDFExtract) that validates its arguments, and the by-name Derive
// which takes Options whose field semantics match the provider
// OSSL_PARAM names, making runtime dispatch straightforward.
package kdf
