package native

/*
#include <openssl/ssl.h>
#include <openssl/err.h>
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
//
// TLS_client_method returns the generic TLS client SSL_METHOD (static
// singleton, do not free). Pass it to SSL_CTX_new to build a client ctx.
func TLS_client_method() unsafe.Pointer {
	return unsafe.Pointer(C.TLS_client_method())
}

// TLS_server_method 返回 TLS 服务端方法。
//
// TLS_server_method returns the generic TLS server SSL_METHOD (static
// singleton, do not free).
func TLS_server_method() unsafe.Pointer {
	return unsafe.Pointer(C.TLS_server_method())
}

// NTLS_method 返回 NTLS（国密 TLCP）方法。
//
// NTLS_method returns the Tongsuo-specific NTLS (TLCP, GM/T 0024) SSL_METHOD
// (static singleton, do not free). Use it with SSL_CTX_new and pair it with
// SSL_CTX_enable_ntls to enable NTLS protocol selection.
func NTLS_method() unsafe.Pointer {
	return unsafe.Pointer(C.NTLS_method())
}

// SSL_CTX_new 创建新的 SSL_CTX。
//
// SSL_CTX_new allocates a new SSL_CTX using method (typically TLS_client_method,
// TLS_server_method, or NTLS_method). The caller owns the returned ctx and
// must release it with SSL_CTX_free. A freshly created ctx has no cert or
// key; SSL_CTX_check_private_key must succeed before the ctx is usable.
func SSL_CTX_new(method unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.SSL_CTX_new((*C.SSL_METHOD)(method)))
}

// SSL_CTX_free 释放 SSL_CTX。
//
// SSL_CTX_free releases ctx; any SSL created from it must not be used after
// the ctx is freed. Safe on NULL.
func SSL_CTX_free(ctx unsafe.Pointer) {
	C.SSL_CTX_free((*C.SSL_CTX)(ctx))
}

// SSL_CTX_enable_ntls 启用国密 NTLS。
//
// SSL_CTX_enable_ntls (Tongsuo extension) enables the NTLS (TLCP) protocol
// on ctx. The ctx should already be built from NTLS_method.
func SSL_CTX_enable_ntls(ctx unsafe.Pointer) {
	C.SSL_CTX_enable_ntls((*C.SSL_CTX)(ctx))
}

// SSL_CTX_use_certificate 设置证书（TLS 单证书）。
//
// SSL_CTX_use_certificate installs cert as the TLS leaf certificate. For NTLS
// (sign / encrypt dual-cert), use SSL_CTX_use_sign_certificate /
// SSL_CTX_use_enc_certificate instead. Returns true on success.
func SSL_CTX_use_certificate(ctx, cert unsafe.Pointer) bool {
	return C.SSL_CTX_use_certificate((*C.SSL_CTX)(ctx), (*C.X509)(cert)) == 1
}

// SSL_CTX_use_PrivateKey 设置私钥（TLS 单证书）。
//
// SSL_CTX_use_PrivateKey installs pkey as the TLS leaf private key. For NTLS
// use SSL_CTX_use_sign_PrivateKey / SSL_CTX_use_enc_PrivateKey instead.
// Returns true on success.
func SSL_CTX_use_PrivateKey(ctx, pkey unsafe.Pointer) bool {
	return C.SSL_CTX_use_PrivateKey((*C.SSL_CTX)(ctx), (*C.EVP_PKEY)(pkey)) == 1
}

// SSL_CTX_use_sign_certificate 设置 NTLS 签名证书。
//
// SSL_CTX_use_sign_certificate (Tongsuo NTLS) installs cert as the NTLS
// signing certificate. Always pair it with SSL_CTX_use_sign_PrivateKey and
// call SSL_CTX_check_private_key before use.
func SSL_CTX_use_sign_certificate(ctx, cert unsafe.Pointer) bool {
	return C.SSL_CTX_use_sign_certificate((*C.SSL_CTX)(ctx), (*C.X509)(cert)) == 1
}

// SSL_CTX_use_enc_certificate 设置 NTLS 加密证书。
//
// SSL_CTX_use_enc_certificate (Tongsuo NTLS) installs cert as the NTLS
// encryption certificate. Always pair it with SSL_CTX_use_enc_PrivateKey
// and call SSL_CTX_check_private_key before use.
func SSL_CTX_use_enc_certificate(ctx, cert unsafe.Pointer) bool {
	return C.SSL_CTX_use_enc_certificate((*C.SSL_CTX)(ctx), (*C.X509)(cert)) == 1
}

// SSL_CTX_use_sign_PrivateKey 设置 NTLS 签名私钥。
//
// SSL_CTX_use_sign_PrivateKey (Tongsuo NTLS) installs pkey as the NTLS
// signing private key. Returns true on success.
func SSL_CTX_use_sign_PrivateKey(ctx, pkey unsafe.Pointer) bool {
	return C.SSL_CTX_use_sign_PrivateKey((*C.SSL_CTX)(ctx), (*C.EVP_PKEY)(pkey)) == 1
}

// SSL_CTX_use_enc_PrivateKey 设置 NTLS 加密私钥。
//
// SSL_CTX_use_enc_PrivateKey (Tongsuo NTLS) installs pkey as the NTLS
// encryption private key. Returns true on success.
func SSL_CTX_use_enc_PrivateKey(ctx, pkey unsafe.Pointer) bool {
	return C.SSL_CTX_use_enc_PrivateKey((*C.SSL_CTX)(ctx), (*C.EVP_PKEY)(pkey)) == 1
}

// SSL_CTX_check_private_key 校验私钥与证书匹配。
//
// SSL_CTX_check_private_key verifies that the configured private key matches
// the configured certificate. MUST be called after setting the cert and key
// (NTLS: both sign and enc pairs) and before using the ctx.
func SSL_CTX_check_private_key(ctx unsafe.Pointer) bool {
	return C.SSL_CTX_check_private_key((*C.SSL_CTX)(ctx)) == 1
}

// SSL_CTX_set_cipher_list 设置可用密码套件。
//
// SSL_CTX_set_cipher_list restricts ctx to the colon-separated cipher list
// (OpenSSL cipher-string syntax, e.g. "ECDHE-SM2-SM4-GCM-SM3" for NTLS).
// Returns true on success.
func SSL_CTX_set_cipher_list(ctx unsafe.Pointer, ciphers string) bool {
	cStr := C.CString(ciphers)
	defer C.free(unsafe.Pointer(cStr))
	return C.SSL_CTX_set_cipher_list((*C.SSL_CTX)(ctx), cStr) == 1
}

// SSL_CTX_set_min_proto_version 设置最低协议版本（经 SSL_CTX_ctrl 规避宏）。
//
// SSL_CTX_set_min_proto_version wraps SSL_CTX_ctrl with
// SSLCtrlSetMinProtoVersion; version is one of the TLS1Version constants
// or NTLSVersion. Returns true on success (>=0 return from the C call).
func SSL_CTX_set_min_proto_version(ctx unsafe.Pointer, version int) bool {
	return C.SSL_CTX_ctrl((*C.SSL_CTX)(ctx), C.int(SSLCtrlSetMinProtoVersion),
		C.long(version), nil) >= 0
}

// SSL_CTX_set_max_proto_version 设置最高协议版本（经 SSL_CTX_ctrl 规避宏）。
//
// SSL_CTX_set_max_proto_version wraps SSL_CTX_ctrl with
// SSLCtrlSetMaxProtoVersion; version is one of the TLS1Version constants
// or NTLSVersion. Returns true on success.
func SSL_CTX_set_max_proto_version(ctx unsafe.Pointer, version int) bool {
	return C.SSL_CTX_ctrl((*C.SSL_CTX)(ctx), C.int(SSLCtrlSetMaxProtoVersion),
		C.long(version), nil) >= 0
}

// SSL_new 创建新的 SSL。
//
// SSL_new allocates a new SSL connection object from ctx. The caller owns
// the returned SSL and must release it with SSL_free.
func SSL_new(ctx unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.SSL_new((*C.SSL_CTX)(ctx)))
}

// SSL_free 释放 SSL。
//
// SSL_free releases ssl; the underlying ctx must outlive ssl. Safe on NULL.
func SSL_free(ssl unsafe.Pointer) {
	C.SSL_free((*C.SSL)(ssl))
}

// SSL_set_fd 绑定套接字 fd。
//
// SSL_set_fd attaches the OS file descriptor fd to ssl for the subsequent
// handshake and I/O. Returns true on success.
func SSL_set_fd(ssl unsafe.Pointer, fd int) bool {
	return C.SSL_set_fd((*C.SSL)(ssl), C.int(fd)) == 1
}

// SSL_connect 发起客户端握手。返回 SSL_read/SSL_write 风格的返回值。
//
// SSL_connect drives the client-side TLS handshake on ssl. The return value
// follows the SSL_read/SSL_write convention: 1 = success, <=0 indicates
// error or want-read/write (consult SSL_get_error).
func SSL_connect(ssl unsafe.Pointer) int {
	return int(C.SSL_connect((*C.SSL)(ssl)))
}

// SSL_accept 接受服务端握手。
//
// SSL_accept drives the server-side TLS handshake on ssl. Returns 1 on
// success; <=0 indicates error or want-read/write (consult SSL_get_error).
func SSL_accept(ssl unsafe.Pointer) int {
	return int(C.SSL_accept((*C.SSL)(ssl)))
}

// SSL_shutdown 关闭 TLS 连接。
//
// SSL_shutdown sends the close_notify alert. Returns 1 on a clean two-way
// shutdown, 0 when only one direction has been shut down, -1 on error.
func SSL_shutdown(ssl unsafe.Pointer) int {
	return int(C.SSL_shutdown((*C.SSL)(ssl)))
}

// SSL_read 读取解密数据。
//
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
//
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
//
// SSL_get_error classifies the ret code returned by SSL_connect, SSL_accept,
// SSL_read, or SSL_write into one of the SSLError* values.
func SSL_get_error(ssl unsafe.Pointer, ret int) int {
	return int(C.SSL_get_error((*C.SSL)(ssl), C.int(ret)))
}

// SSL_get_version 返回协议版本字符串。
//
// SSL_get_version returns the negotiated protocol version as a string
// (e.g. "TLSv1.2", "TLSv1.3", "NTLS" for TLCP).
func SSL_get_version(ssl unsafe.Pointer) string {
	return C.GoString(C.SSL_get_version((*C.SSL)(ssl)))
}

// SSL_get_current_cipher_name 返回当前密码套件名。
//
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
