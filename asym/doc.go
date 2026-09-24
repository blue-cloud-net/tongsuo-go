// Package asym 是铜锁非对称算法（SM2 / RSA / ECDSA / Ed25519 / Ed448 /
// X25519 / X448）的统一入口。
//
// 本包按算法名分发：每种算法有专属函数（如 GenerateSM2 / SignPSS /
// SignEd25519），同时保留 CLI 式高层入口（如 GenerateKey(alg, opts)）。
//
// 所有公开密钥对象对外只暴露 PrivateKey / PublicKey 接口，具体类型非导出。
// 内部句柄访问走 internal/keyaccess 桥接（详见 internal/keyaccess 与 docs/
// refactor-roadmap.md §5.2）。
//
// Package asym is the unified entry point for the Tongsuo asymmetric
// algorithms (SM2 / RSA / ECDSA / Ed25519 / Ed448 / X25519 / X448).
//
// The package dispatches by algorithm name: each algorithm has typed
// entry points (such as GenerateSM2 / SignPSS / SignEd25519) and CLI-style
// generic entry points (such as GenerateKey(alg, opts)).
//
// All public key objects expose only the PrivateKey / PublicKey
// interfaces; the concrete types are unexported. Internal handle access
// goes through the internal/keyaccess bridge (see internal/keyaccess and
// docs/refactor-roadmap.md §5.2).
package asym
