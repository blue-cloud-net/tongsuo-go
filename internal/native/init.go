package native

/*
#include <openssl/crypto.h>
*/
import "C"

// init 确保铜锁在首次使用前完成初始化。
//
// 注意：Tongsuo 8.x 基于 OpenSSL 3.x，默认线程安全，
// 无需（也不应）像 OpenSSL 1.0 时代那样注册自定义线程锁回调。
// 此处显式调用 OPENSSL_init_crypto 以尽早完成默认初始化（幂等）。
//
// init ensures Tongsuo completes its default initialization before
// first use. Tongsuo 8.x is built on OpenSSL 3.x and is thread-safe
// by default; unlike the OpenSSL 1.0 era, no custom thread-lock
// callbacks need (or should) be registered. This init() calls
// OPENSSL_init_crypto to trigger Tongsuo's default initialization
// eagerly; the call is idempotent.
func init() {
	C.OPENSSL_init_crypto(0, nil)
}
