//go:build !static

// Package native 是 tongsuo-go 的绑定层：通过 cgo 直接映射铜锁 (Tongsuo) 的 C 函数。
//
// 本包属于 internal 实现，禁止被库外部导入；对外 API 见 crypto 子包。
// 各功能域的绑定按文件拆分（binding_*.go），函数名与铜锁原生 C 函数名一致。
//
// Package native is tongsuo-go's binding layer: it maps Tongsuo C
// functions to Go via cgo. It is an internal implementation and must
// not be imported outside the library; public APIs live under the
// crypto subpackages. Bindings are split per feature into
// binding_*.go files, and each helper mirrors the name of its
// underlying Tongsuo C function.
package native

/*
#cgo CFLAGS: -I/opt/tongsuo/include -Wno-deprecated-declarations

// 注意：链接顺序必须是 -lssl -lcrypto（消费者在前，提供者在后）。
// libssl.a 引用 libcrypto.a 的符号（X509_LOOKUP_*、OSSL_STORE_*、CT_POLICY_* 等）。
// 静态归档按从左到右扫描并按需拉入目标；若把 -lcrypto 放在 -lssl 前，
// 处理 libssl.a 时已没有再走一遍 libcrypto.a 的机会，从而报
// "undefined reference"（CI 用 no-shared 编译时 100% 复现）。
// 对动态库（.so）顺序无所谓，但保持一致更稳妥。
#cgo linux LDFLAGS: -L/opt/tongsuo/lib64 -Wl,-rpath,/opt/tongsuo/lib64 -lssl -lcrypto
#cgo darwin LDFLAGS: -L/opt/tongsuo/lib64 -Wl,-rpath,/opt/tongsuo/lib64 -lssl -lcrypto
*/
import "C"
