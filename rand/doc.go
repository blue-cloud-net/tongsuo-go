// Package rand 基于铜锁原生实现提供加密安全随机数生成。
//
// 与标准库 crypto/rand 的区别：本包底层走 Tongsuo RAND_bytes（OpenSSL CSPRNG），
// stdlib crypto/rand 在 Linux 上走 getrandom(2)。两者均属密码学安全随机数，
// 输出可用于密钥材料、nonce、salt 与 IV。
//
// 包路径由 crypto/rand 改为 rand（顶级），消除与标准库 crypto/rand 同路径
// 的陷阱（重构后调用方不再需要别名）。同一文件同时 import stdlib crypto/rand
// 与本包时仍需别名（包名相同）。
//
// Package rand provides a cryptographically secure random byte generator
// backed by the Tongsuo native library (OpenSSL CSPRNG via RAND_bytes).
//
// Unlike stdlib crypto/rand (which on Linux uses getrandom(2)), this
// package sources entropy through Tongsuo's RAND_bytes. Both are
// cryptographically secure and the output is suitable for key
// material, nonces, salts and IVs.
//
// The import path moved from crypto/rand to the top-level rand to
// remove the stdlib-path collision; callers that import both this
// package and stdlib crypto/rand in the same file still need an
// explicit alias because the package name remains rand.
package rand
