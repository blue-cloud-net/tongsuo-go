package core

import (
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// ZeroBytes 安全清零一段承载密钥材料或口令的字节切片。
//
// 内部转发到 OPENSSL_cleanse：通过 volitile 函数指针绕过编译器的"未引用
// memcpy/memset 消除"优化，确保 release 构建里数据真的被覆写。
//
// 使用场景：
//   - 从 PEM/PKCS#12 解密出来的口令副本
//   - 临时保存口令的 byte slice（解密后立即 wipe）
//   - 任何不再需要的密钥材料副本
//
// 注意：Go string 不可变，无法通过本函数清零；如需清零应改用 []byte。
// nil 或 len==0 时为 no-op。
//
// ZeroBytes securely zeroes a byte slice that carried key material or a
// passphrase.
//
// It dispatches to OPENSSL_cleanse, which routes through a volatile
// function pointer to prevent the compiler from optimising away the
// memset in release builds (a hazard with naive runtime.memclr or
// hand-written loops).
//
// Use it to wipe:
//   - passphrase copies obtained from PEM/PKCS#12 decryption
//   - temporary []byte buffers that held passphrases
//   - any cached key-material copy that is no longer needed
//
// Note that Go strings are immutable and cannot be wiped through this
// helper; convert sensitive passphrases to []byte before passing them
// in. nil or len==0 is a no-op.
func ZeroBytes(b []byte) {
	native.Cleanse(b)
}
