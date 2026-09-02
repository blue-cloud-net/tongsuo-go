//go:build static

package native

/*
#cgo CFLAGS: -I/opt/tongsuo/include -Wno-deprecated-declarations

// 注意：链接顺序必须是 -lssl -lcrypto（消费者在前，提供者在后）。
// libssl.a 引用 libcrypto.a 的符号（X509_LOOKUP_*、OSSL_STORE_*、CT_POLICY_* 等）。
// 静态归档按从左到右扫描并按需拉入目标；若把 -lcrypto 放在 -lssl 前，
// 处理 libssl.a 时已没有再走一遍 libcrypto.a 的机会，从而报
// "undefined reference"。
#cgo linux LDFLAGS: -L/opt/tongsuo/lib64 -lssl -lcrypto -ldl -lpthread
*/
import "C"
