package native

/*
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// SSL 错误码常量（ssl.h 宏）。
//
// SSLError* mirror the OpenSSL SSL_ERROR_* codes returned by SSL_get_error
// to disambiguate the return value of SSL_read / SSL_write / SSL_connect /
// SSL_accept.
const (
	SSLErrorNone       = 0
	SSLErrorSSL        = 1
	SSLErrorWantRead   = 2
	SSLErrorWantWrite  = 3
	SSLErrorSyscall    = 5
	SSLErrorZeroReturn = 6
)

// SSL 验证模式常量（ssl.h SSL_VERIFY_*），与 SSL_CTX_set_verify 配合使用。
//
// SSL_VERIFY_* mirror the OpenSSL ssl.h verification mode flags used with
// SSL_CTX_set_verify. They are bitwise-OR-able; pass them through to the
// underlying binding via integer cast.
const (
	SSL_VERIFY_NONE                 = 0x00
	SSL_VERIFY_PEER                 = 0x01
	SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02
	SSL_VERIFY_CLIENT_ONCE          = 0x04
)

// X509_V_OK 为对端验证成功码（0）。其它 X509_V_ERR_* 大量代码未导出，
// 调用方可通过 X509_verify_cert_error_string 取出错误描述。
// X509_V_OK is the success code returned by SSL_get_verify_result.
const X509_V_OK = 0

// SSL_CTX_ctrl 控制类型常量。
//
// SSLCtrlSetMinProtoVersion / SSLCtrlSetMaxProtoVersion are the integer
// control IDs for SSL_CTX_ctrl, used in place of the deprecated macros.
const (
	SSLCtrlSetMinProtoVersion = 123
	SSLCtrlSetMaxProtoVersion = 124
)

// TLS 协议版本常量。
//
// TLS1Version through TLS1_3Version are the standard TLS wire-protocol
// versions; NTLSVersion is the Tongsuo-specific NTLS (TLCP) version byte
// used by NTLS_method.
const (
	TLS1Version   = 0x0301
	TLS1_1Version = 0x0302
	TLS1_2Version = 0x0303
	TLS1_3Version = 0x0304
	NTLSVersion   = 0x0101
)

// TLS_client_method 返回 TLS 客户端方法。
// TLS_client_method returns the generic TLS client SSL_METHOD (static
// singleton, do not free). Pass it to SSL_CTX_new to build a client ctx.
func TLS_client_method() unsafe.Pointer {
	return unsafe.Pointer(C.TLS_client_method())
}

// TLS_server_method 返回 TLS 服务端方法。
// TLS_server_method returns the generic TLS server SSL_METHOD (static
// singleton, do not free).
func TLS_server_method() unsafe.Pointer {
	return unsafe.Pointer(C.TLS_server_method())
}

// NTLS_method 返回 NTLS（国密 TLCP）方法。
// NTLS_method returns the Tongsuo-specific NTLS (TLCP, GM/T 0024) SSL_METHOD
// (static singleton, do not free). Use it with SSL_CTX_new and pair it with
// SSL_CTX_enable_ntls to enable NTLS protocol selection.
func NTLS_method() unsafe.Pointer {
	return unsafe.Pointer(C.NTLS_method())
}

// SSL_CTX_new 创建新的 SSL_CTX。
// SSL_CTX_new allocates a new SSL_CTX using method (typically TLS_client_method,
// TLS_server_method, or NTLS_method). The caller owns the returned ctx and
// must release it with SSL_CTX_free. A freshly created ctx has no cert or
// key; SSL_CTX_check_private_key must succeed before the ctx is usable.
func SSL_CTX_new(method unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.SSL_CTX_new((*C.SSL_METHOD)(method)))
}

// SSL_CTX_free 释放 SSL_CTX。
// SSL_CTX_free releases ctx; any SSL created from it must not be used after
// the ctx is freed. Safe on NULL.
func SSL_CTX_free(ctx unsafe.Pointer) {
	C.SSL_CTX_free((*C.SSL_CTX)(ctx))
}

// SSL_CTX_enable_ntls 启用国密 NTLS。
// SSL_CTX_enable_ntls (Tongsuo extension) enables the NTLS (TLCP) protocol
// on ctx. The ctx should already be built from NTLS_method.
func SSL_CTX_enable_ntls(ctx unsafe.Pointer) {
	C.SSL_CTX_enable_ntls((*C.SSL_CTX)(ctx))
}

// SSL_CTX_use_certificate 设置证书（TLS 单证书）。
// SSL_CTX_use_certificate installs cert as the TLS leaf certificate. For NTLS
// (sign / encrypt dual-cert), use SSL_CTX_use_sign_certificate /
// SSL_CTX_use_enc_certificate instead. Returns true on success.
func SSL_CTX_use_certificate(ctx, cert unsafe.Pointer) bool {
	return C.SSL_CTX_use_certificate((*C.SSL_CTX)(ctx), (*C.X509)(cert)) == 1
}

// SSL_CTX_use_PrivateKey 设置私钥（TLS 单证书）。
// SSL_CTX_use_PrivateKey installs pkey as the TLS leaf private key. For NTLS
// use SSL_CTX_use_sign_PrivateKey / SSL_CTX_use_enc_PrivateKey instead.
// Returns true on success.
func SSL_CTX_use_PrivateKey(ctx, pkey unsafe.Pointer) bool {
	return C.SSL_CTX_use_PrivateKey((*C.SSL_CTX)(ctx), (*C.EVP_PKEY)(pkey)) == 1
}

// SSL_CTX_use_sign_certificate 设置 NTLS 签名证书。
// SSL_CTX_use_sign_certificate (Tongsuo NTLS) installs cert as the NTLS
// signing certificate. Always pair it with SSL_CTX_use_sign_PrivateKey and
// call SSL_CTX_check_private_key before use.
func SSL_CTX_use_sign_certificate(ctx, cert unsafe.Pointer) bool {
	return C.SSL_CTX_use_sign_certificate((*C.SSL_CTX)(ctx), (*C.X509)(cert)) == 1
}

// SSL_CTX_use_enc_certificate 设置 NTLS 加密证书。
// SSL_CTX_use_enc_certificate (Tongsuo NTLS) installs cert as the NTLS
// encryption certificate. Always pair it with SSL_CTX_use_enc_PrivateKey
// and call SSL_CTX_check_private_key before use.
func SSL_CTX_use_enc_certificate(ctx, cert unsafe.Pointer) bool {
	return C.SSL_CTX_use_enc_certificate((*C.SSL_CTX)(ctx), (*C.X509)(cert)) == 1
}

// SSL_CTX_use_sign_PrivateKey 设置 NTLS 签名私钥。
// SSL_CTX_use_sign_PrivateKey (Tongsuo NTLS) installs pkey as the NTLS
// signing private key. Returns true on success.
func SSL_CTX_use_sign_PrivateKey(ctx, pkey unsafe.Pointer) bool {
	return C.SSL_CTX_use_sign_PrivateKey((*C.SSL_CTX)(ctx), (*C.EVP_PKEY)(pkey)) == 1
}

// SSL_CTX_use_enc_PrivateKey 设置 NTLS 加密私钥。
// SSL_CTX_use_enc_PrivateKey (Tongsuo NTLS) installs pkey as the NTLS
// encryption private key. Returns true on success.
func SSL_CTX_use_enc_PrivateKey(ctx, pkey unsafe.Pointer) bool {
	return C.SSL_CTX_use_enc_PrivateKey((*C.SSL_CTX)(ctx), (*C.EVP_PKEY)(pkey)) == 1
}

// SSL_CTX_check_private_key 校验私钥与证书匹配。
// SSL_CTX_check_private_key verifies that the configured private key matches
// the configured certificate. MUST be called after setting the cert and key
// (NTLS: both sign and enc pairs) and before using the ctx.
func SSL_CTX_check_private_key(ctx unsafe.Pointer) bool {
	return C.SSL_CTX_check_private_key((*C.SSL_CTX)(ctx)) == 1
}

// SSL_CTX_set_cipher_list 设置可用密码套件。
// SSL_CTX_set_cipher_list restricts ctx to the colon-separated cipher list
// (OpenSSL cipher-string syntax, e.g. "ECDHE-SM2-SM4-GCM-SM3" for NTLS).
// Returns true on success.
func SSL_CTX_set_cipher_list(ctx unsafe.Pointer, ciphers string) bool {
	cStr := C.CString(ciphers)
	defer C.free(unsafe.Pointer(cStr))
	return C.SSL_CTX_set_cipher_list((*C.SSL_CTX)(ctx), cStr) == 1
}

// SSL_CTX_set_min_proto_version 设置最低协议版本（经 SSL_CTX_ctrl 规避宏）。
// SSL_CTX_set_min_proto_version wraps SSL_CTX_ctrl with
// SSLCtrlSetMinProtoVersion; version is one of the TLS1Version constants
// or NTLSVersion. Returns true on success (>=0 return from the C call).
func SSL_CTX_set_min_proto_version(ctx unsafe.Pointer, version int) bool {
	return C.SSL_CTX_ctrl((*C.SSL_CTX)(ctx), C.int(SSLCtrlSetMinProtoVersion),
		C.long(version), nil) >= 0
}

// SSL_CTX_set_max_proto_version 设置最高协议版本（经 SSL_CTX_ctrl 规避宏）。
// SSL_CTX_set_max_proto_version wraps SSL_CTX_ctrl with
// SSLCtrlSetMaxProtoVersion; version is one of the TLS1Version constants
// or NTLSVersion. Returns true on success.
func SSL_CTX_set_max_proto_version(ctx unsafe.Pointer, version int) bool {
	return C.SSL_CTX_ctrl((*C.SSL_CTX)(ctx), C.int(SSLCtrlSetMaxProtoVersion),
		C.long(version), nil) >= 0
}

// SSL_new 创建新的 SSL。
// SSL_new allocates a new SSL connection object from ctx. The caller owns
// the returned SSL and must release it with SSL_free.
func SSL_new(ctx unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.SSL_new((*C.SSL_CTX)(ctx)))
}

// SSL_free 释放 SSL。
// SSL_free releases ssl; the underlying ctx must outlive ssl. Safe on NULL.
func SSL_free(ssl unsafe.Pointer) {
	C.SSL_free((*C.SSL)(ssl))
}

// SSL_set_fd 绑定套接字 fd。
// SSL_set_fd attaches the OS file descriptor fd to ssl for the subsequent
// handshake and I/O. Returns true on success.
func SSL_set_fd(ssl unsafe.Pointer, fd int) bool {
	return C.SSL_set_fd((*C.SSL)(ssl), C.int(fd)) == 1
}

// SSL_connect 发起客户端握手。返回 SSL_read/SSL_write 风格的返回值。
// SSL_connect drives the client-side TLS handshake on ssl. The return value
// follows the SSL_read/SSL_write convention: 1 = success, <=0 indicates
// error or want-read/write (consult SSL_get_error).
func SSL_connect(ssl unsafe.Pointer) int {
	return int(C.SSL_connect((*C.SSL)(ssl)))
}

// SSL_accept 接受服务端握手。
// SSL_accept drives the server-side TLS handshake on ssl. Returns 1 on
// success; <=0 indicates error or want-read/write (consult SSL_get_error).
func SSL_accept(ssl unsafe.Pointer) int {
	return int(C.SSL_accept((*C.SSL)(ssl)))
}

// SSL_shutdown 关闭 TLS 连接。
// SSL_shutdown sends the close_notify alert. Returns 1 on a clean two-way
// shutdown, 0 when only one direction has been shut down, -1 on error.
func SSL_shutdown(ssl unsafe.Pointer) int {
	return int(C.SSL_shutdown((*C.SSL)(ssl)))
}

// SSL_read 读取解密数据。
// SSL_read decrypts up to len(buf) bytes from ssl into buf. Returns the
// number of bytes read, 0 on EOF, or -1 on error / want-read/write (use
// SSL_get_error to disambiguate).
func SSL_read(ssl unsafe.Pointer, buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	return int(C.SSL_read((*C.SSL)(ssl), unsafe.Pointer(&buf[0]), C.int(len(buf))))
}

// SSL_write 写入待加密数据。
// SSL_write encrypts len(buf) bytes from buf and sends them to the peer.
// Returns the number of bytes written, or -1 on error / want-read/write
// (consult SSL_get_error).
func SSL_write(ssl unsafe.Pointer, buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	return int(C.SSL_write((*C.SSL)(ssl), unsafe.Pointer(&buf[0]), C.int(len(buf))))
}

// SSL_get_error 返回 SSL 错误码。
// SSL_get_error classifies the ret code returned by SSL_connect, SSL_accept,
// SSL_read, or SSL_write into one of the SSLError* values.
func SSL_get_error(ssl unsafe.Pointer, ret int) int {
	return int(C.SSL_get_error((*C.SSL)(ssl), C.int(ret)))
}

// SSL_get_version 返回协议版本字符串。
// SSL_get_version returns the negotiated protocol version as a string
// (e.g. "TLSv1.2", "TLSv1.3", "NTLS" for TLCP).
func SSL_get_version(ssl unsafe.Pointer) string {
	return C.GoString(C.SSL_get_version((*C.SSL)(ssl)))
}

// SSL_get_current_cipher_name 返回当前密码套件名。
// SSL_get_current_cipher_name returns the OpenSSL name of the negotiated
// cipher (e.g. "ECDHE-SM2-SM4-GCM-SM3" for NTLS). Returns "" if no cipher
// has been negotiated yet.
func SSL_get_current_cipher_name(ssl unsafe.Pointer) string {
	cipher := C.SSL_get_current_cipher((*C.SSL)(ssl))
	if cipher == nil {
		return ""
	}
	return C.GoString(C.SSL_CIPHER_get_name(cipher))
}

/*
 * 对端证书验证（Phase 1.8）：SSL_VERIFY_* 模式常量与相关绑定。
 *
 * 模式取值（来自 OpenSSL ssl.h，与 Tongsuo 兼容）：
 *   SSL_VERIFY_NONE                 = 0x00  // 不验证对端
 *   SSL_VERIFY_PEER                 = 0x01  // 验证对端证书
 *   SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02  // 对端无证书则握手失败（用于服务端）
 *   SSL_VERIFY_CLIENT_ONCE          = 0x04  // 仅对第一次重协商请求客户端证书
 *
 * X509_V_OK = 0 表示验证成功；其它值见 OpenSSL x509_vfy.h。本库不对
 * 所有 X509_V_ERR_* 暴露常量；调用方需要详细诊断时可借助
 * X509_verify_cert_error_string（在 binding_x509.go 中已绑定）。
 */

// SSL_CTX_set_verify 设置对端证书验证模式（callback 固定为 NULL，使用 Tongsuo 内建验证）。
//
// 经 shim 函数 X_SSL_CTX_set_verify 间接调用：cgo 不允许把 untyped nil
// 当作 SSL_verify_cb 函数指针传入 C 函数，所以 callback 由 C 侧固定为 NULL。
//
// SSL_CTX_set_verify sets the peer verification mode for ctx. The verify
// callback is fixed to NULL inside the C shim (cgo disallows passing a
// nil function pointer across the boundary); Tongsuo performs its
// built-in chain validation.
func SSL_CTX_set_verify(ctx unsafe.Pointer, mode int) bool {
	C.X_SSL_CTX_set_verify((*C.SSL_CTX)(ctx), C.int(mode))
	return true
}

// SSL_CTX_set_verify_depth 设置对端证书链验证最大深度（经 shim 函数 X_SSL_CTX_set_verify_depth 包装）。
// SSL_CTX_set_verify_depth sets the chain validation depth limit for ctx
// (the number of CA certificates that may follow the peer certificate).
func SSL_CTX_set_verify_depth(ctx unsafe.Pointer, depth int) bool {
	C.X_SSL_CTX_set_verify_depth((*C.SSL_CTX)(ctx), C.int(depth))
	return true
}

// SSL_CTX_set_default_verify_paths 加载系统/编译期配置的默认 CA 证书路径（经 shim 函数 X_SSL_CTX_set_default_verify_paths 包装）。
// SSL_CTX_set_default_verify_paths loads the system (or OpenSSL-configured)
// default CA certificate locations onto ctx's trust store.
func SSL_CTX_set_default_verify_paths(ctx unsafe.Pointer) bool {
	return C.X_SSL_CTX_set_default_verify_paths((*C.SSL_CTX)(ctx)) == 1
}

// SSL_CTX_get_cert_store 获取 ctx 自带的证书信任库（首次调用自动创建）。
// 返回的 X509_STORE 由 ctx 拥有，调用方不得 free。
// SSL_CTX_get_cert_store returns the X509_STORE owned by ctx. The store is
// created on first use and is owned by ctx; the caller must NOT free it.
func SSL_CTX_get_cert_store(ctx unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.SSL_CTX_get_cert_store((*C.SSL_CTX)(ctx)))
}

// SSL_set1_host 在 SSL 句柄上设置 SNI/主机名（用于主机名校验；指针被 SSL_set1_host 内部复制）。
// 调用方传入空字符串或 nil 不报错但无效果。
// SSL_set1_host sets the expected peer hostname on ssl (used for hostname
// verification). The hostname is copied internally; passing "" or nil is
// accepted but has no effect.
func SSL_set1_host(ssl unsafe.Pointer, hostname string) bool {
	if hostname == "" {
		return true
	}
	c := C.CString(hostname)
	defer C.free(unsafe.Pointer(c))
	return C.SSL_set1_host((*C.SSL)(ssl), c) == 1
}

// SSL_set_tlsext_host_name 在 ClientHello 中设置 SNI（server_name 扩展）。
//
// 与 SSL_set1_host 是**两件不同的事**，必须分别调用：
//   - SSL_set_tlsext_host_name（本函数）：告诉服务端"我要访问哪个域名"，属于
//     路由信息 —— 缺它时多数真实站点（CDN / 虚拟主机）直接回
//     `sslv3 alert handshake failure`（alert 40），握手在证书验证之前就失败；
//   - SSL_set1_host：校验对端证书是否为该域名签发，属于验证信息。
//
// 因此即使客户端为 VERIFY_NONE（不校验证书），也**必须**发送 SNI。
// 空字符串或 nil 不报错但无效果。
//
// SSL_set_tlsext_host_name sets the SNI (server_name) extension in the
// ClientHello. This is routing information and is independent of certificate
// verification: without it most real-world servers abort the handshake with
// `sslv3 alert handshake failure` (alert 40) before any verification happens.
// Passing "" is accepted but has no effect.
func SSL_set_tlsext_host_name(ssl unsafe.Pointer, hostname string) bool {
	if hostname == "" {
		return true
	}
	c := C.CString(hostname)
	defer C.free(unsafe.Pointer(c))
	return C.X_SSL_set_tlsext_host_name((*C.SSL)(ssl), c) == 1
}

// SSL_get_verify_result 返回最近一次对端验证的结果码（X509_V_OK=0 表示成功）。
// 仅在 SSL_VERIFY_PEER 模式下有意义；握手未完成或模式关闭时返回 -1。
// SSL_get_verify_result returns the result code of the most recent peer
// certificate validation (X509_V_OK == 0 on success). Returns -1 when no
// validation has been performed or the mode is disabled.
func SSL_get_verify_result(ssl unsafe.Pointer) int {
	return int(C.SSL_get_verify_result((*C.SSL)(ssl)))
}

// SSL_get_peer_certificate 返回对端证书副本（owned），调用方负责 X509_free。
// 无对端证书时返回 nil。
// SSL_get_peer_certificate returns a copy of the peer's certificate (the
// caller owns it and must X509_free). Returns nil when no peer cert was
// presented.
func SSL_get_peer_certificate(ssl unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.SSL_get_peer_certificate((*C.SSL)(ssl)))
}

// X509_free 由 binding_x509.go 导出，PeerCertificate 直接复用。

/*
 * Phase v0.1.2：套件枚举与对端证书链。
 *
 * 历史背景（调研）：OpenSSL/Tongsuo 8.x 没有「枚举 ctx 上全部可用
 * 套件」的标准 API 公开宏。常见做法是直接读 ctx->cipher_list 内部字段，
 * 或走 sk_SSL_CIPHER_* 宏（受 ossl_check_SSL_CIPHER_sk_type 类型检查）。
 * 这里经 shim 规避：shim 函数以 void * 收 SSL_CTX / STACK_OF(SSL_CIPHER) /
 * SSL_CIPHER，再转回原生类型；Go 侧只看 unsafe.Pointer 与标量。
 */

// SSL_CIPHER_get_name 返回套件的 OpenSSL 名（如 "ECDHE-SM2-SM4-GCM-SM3"）。
// 失败（nil 套件）返回空串。
//
// SSL_CIPHER_get_name returns the OpenSSL name of cipher (for example
// "ECDHE-SM2-SM4-GCM-SM3"). Returns the empty string for a nil cipher.
func SSL_CIPHER_get_name(cipher unsafe.Pointer) string {
	if cipher == nil {
		return ""
	}
	p := (*C.char)(C.X_SSL_CIPHER_get_name(cipher))
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// SSL_CIPHER_get_id 返回 32 位编码的套件 ID（与 OpenSSL 标准格式一致）。
//
// SSL_CIPHER_get_id returns the 32-bit cipher identifier in OpenSSL
// encoding. Note that the lower 16 bits form the IANA wire ID surfaced as
// CipherSuiteInfo.ID.
func SSL_CIPHER_get_id(cipher unsafe.Pointer) uint32 {
	if cipher == nil {
		return 0
	}
	return uint32(C.X_SSL_CIPHER_get_id(cipher))
}

// SSL_CIPHER_get_protocol_id 返回 16 位 IANA 协议 ID（与 TLS CipherSuite
// wire number 一致；NTLS 套件返回 Tongsuo 自定义编码如 0x0300E051）。
//
// SSL_CIPHER_get_protocol_id returns the 16-bit IANA cipher wire ID; for
// NTLS ciphers the value is the Tongsuo private range (e.g. 0x0300E051).
// Returns 0 for a nil cipher.
func SSL_CIPHER_get_protocol_id(cipher unsafe.Pointer) uint16 {
	if cipher == nil {
		return 0
	}
	return uint16(C.X_SSL_CIPHER_get_protocol_id(cipher))
}

// SSL_CIPHER_get_version 返回套件适用的协议版本字符串（"TLSv1.0"/"TLSv1.2"/
// "TLSv1.3"/"NTLSv1.1"），对应 c->min_tls 经 SSL_CIPHER_get_version 内部
// 处理。
//
// SSL_CIPHER_get_version returns the minimum-TLS version string for cipher
// (for example "TLSv1.2", "TLSv1.3", "NTLSv1.1"). Returns "" for a nil
// cipher.
func SSL_CIPHER_get_version(cipher unsafe.Pointer) string {
	if cipher == nil {
		return ""
	}
	p := (*C.char)(C.X_SSL_CIPHER_get_version_str(cipher))
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// SSL_CTX_get_ciphers 返回 ctx 上当前启用的全部套件栈（STACK_OF(SSL_CIPHER)*）。
// 栈由 ctx 拥有，不可 free；元素 SSL_CIPHER* 也由 ctx 拥有，遍历时勿 free。
// TLS1.3 套件排在最前。空集 / 失败返回 nil。
//
// SSL_CTX_get_ciphers returns the cipher stack currently enabled on ctx.
// The stack is owned by ctx (do not free); each SSL_CIPHER* is also owned
// by ctx (do not free). TLS1.3 ciphers are placed first. Returns nil when
// the stack is empty or unavailable.
func SSL_CTX_get_ciphers(ctx unsafe.Pointer) unsafe.Pointer {
	if ctx == nil {
		return nil
	}
	return unsafe.Pointer(C.X_SSL_CTX_get_ciphers(ctx))
}

// SSL_CIPHER_sk_num 返回栈中套件数量。
//
// SSL_CIPHER_sk_num returns the number of ciphers in the stack. Returns 0
// for a nil stack.
func SSL_CIPHER_sk_num(sk unsafe.Pointer) int {
	if sk == nil {
		return 0
	}
	return int(C.X_SSL_CIPHER_sk_num(sk))
}

// SSL_CIPHER_sk_value 返回第 i 个套件（内部指针，勿 free）。
//
// SSL_CIPHER_sk_value returns the i-th cipher as an internal pointer; do
// NOT free. Returns nil for out-of-range indices.
func SSL_CIPHER_sk_value(sk unsafe.Pointer, i int) unsafe.Pointer {
	if sk == nil {
		return nil
	}
	return unsafe.Pointer(C.X_SSL_CIPHER_sk_value(sk, C.int(i)))
}

// SSL_CTX_set_ciphersuites 设置 TLS1.3 套件名单（OpenSSL 标准名）。
// 成功返回 true；空字符串与"ALL"等别名不会被识别（仅认 standard name）。
//
// SSL_CTX_set_ciphersuites restricts ctx to the colon-separated list of
// TLS1.3 ciphersuites (OpenSSL standard names such as "TLS_AES_128_GCM_SHA256").
// Returns true on success. The "ALL" alias is NOT recognised — pass an
// explicit list or the value returned by OSSL_default_ciphersuites(1).
func SSL_CTX_set_ciphersuites(ctx unsafe.Pointer, list string) bool {
	if ctx == nil {
		return false
	}
	if list == "" {
		return true
	}
	c := C.CString(list)
	defer C.free(unsafe.Pointer(c))
	return C.X_SSL_CTX_set_ciphersuites(ctx, c) == 1
}

// SSL_get_peer_cert_chain 返回对端证书链（STACK_OF(X509)*，内部栈，勿 free）。
// 单张对端证书可用 SSL_get_peer_certificate 单独取。
//
// SSL_get_peer_cert_chain returns the peer's certificate chain as the
// internal session->peer_chain stack. The stack and elements are owned
// by the SSL session; do NOT free. For a single peer cert, use
// SSL_get_peer_certificate instead.
func SSL_get_peer_cert_chain(ssl unsafe.Pointer) unsafe.Pointer {
	if ssl == nil {
		return nil
	}
	return unsafe.Pointer(C.X_SSL_get_peer_cert_chain(ssl))
}
