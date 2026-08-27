package native

/*
#include <openssl/ssl.h>
#include <openssl/err.h>
*/
import "C"
import "unsafe"

// SSL 错误码常量（ssl.h 宏）。
const (
	SSLErrorNone       = 0
	SSLErrorSSL        = 1
	SSLErrorWantRead   = 2
	SSLErrorWantWrite  = 3
	SSLErrorSyscall    = 5
	SSLErrorZeroReturn = 6
)

// SSL_CTX_ctrl 控制类型常量。
const (
	SSLCtrlSetMinProtoVersion = 123
	SSLCtrlSetMaxProtoVersion = 124
)

// TLS 协议版本常量。
const (
	TLS1Version   = 0x0301
	TLS1_1Version = 0x0302
	TLS1_2Version = 0x0303
	TLS1_3Version = 0x0304
	NTLSVersion   = 0x0101
)

// TLS_client_method 返回 TLS 客户端方法。
func TLS_client_method() unsafe.Pointer {
	return unsafe.Pointer(C.TLS_client_method())
}

// TLS_server_method 返回 TLS 服务端方法。
func TLS_server_method() unsafe.Pointer {
	return unsafe.Pointer(C.TLS_server_method())
}

// NTLS_method 返回 NTLS（国密 TLCP）方法。
func NTLS_method() unsafe.Pointer {
	return unsafe.Pointer(C.NTLS_method())
}

// SSL_CTX_new 创建新的 SSL_CTX。
func SSL_CTX_new(method unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.SSL_CTX_new((*C.SSL_METHOD)(method)))
}

// SSL_CTX_free 释放 SSL_CTX。
func SSL_CTX_free(ctx unsafe.Pointer) {
	C.SSL_CTX_free((*C.SSL_CTX)(ctx))
}

// SSL_CTX_enable_ntls 启用国密 NTLS。
func SSL_CTX_enable_ntls(ctx unsafe.Pointer) {
	C.SSL_CTX_enable_ntls((*C.SSL_CTX)(ctx))
}

// SSL_CTX_use_certificate 设置证书（TLS 单证书）。
func SSL_CTX_use_certificate(ctx, cert unsafe.Pointer) bool {
	return C.SSL_CTX_use_certificate((*C.SSL_CTX)(ctx), (*C.X509)(cert)) == 1
}

// SSL_CTX_use_PrivateKey 设置私钥（TLS 单证书）。
func SSL_CTX_use_PrivateKey(ctx, pkey unsafe.Pointer) bool {
	return C.SSL_CTX_use_PrivateKey((*C.SSL_CTX)(ctx), (*C.EVP_PKEY)(pkey)) == 1
}

// SSL_CTX_use_sign_certificate 设置 NTLS 签名证书。
func SSL_CTX_use_sign_certificate(ctx, cert unsafe.Pointer) bool {
	return C.SSL_CTX_use_sign_certificate((*C.SSL_CTX)(ctx), (*C.X509)(cert)) == 1
}

// SSL_CTX_use_enc_certificate 设置 NTLS 加密证书。
func SSL_CTX_use_enc_certificate(ctx, cert unsafe.Pointer) bool {
	return C.SSL_CTX_use_enc_certificate((*C.SSL_CTX)(ctx), (*C.X509)(cert)) == 1
}

// SSL_CTX_use_sign_PrivateKey 设置 NTLS 签名私钥。
func SSL_CTX_use_sign_PrivateKey(ctx, pkey unsafe.Pointer) bool {
	return C.SSL_CTX_use_sign_PrivateKey((*C.SSL_CTX)(ctx), (*C.EVP_PKEY)(pkey)) == 1
}

// SSL_CTX_use_enc_PrivateKey 设置 NTLS 加密私钥。
func SSL_CTX_use_enc_PrivateKey(ctx, pkey unsafe.Pointer) bool {
	return C.SSL_CTX_use_enc_PrivateKey((*C.SSL_CTX)(ctx), (*C.EVP_PKEY)(pkey)) == 1
}

// SSL_CTX_check_private_key 校验私钥与证书匹配。
func SSL_CTX_check_private_key(ctx unsafe.Pointer) bool {
	return C.SSL_CTX_check_private_key((*C.SSL_CTX)(ctx)) == 1
}

// SSL_CTX_set_cipher_list 设置可用密码套件。
func SSL_CTX_set_cipher_list(ctx unsafe.Pointer, ciphers string) bool {
	cStr := C.CString(ciphers)
	defer C.free(unsafe.Pointer(cStr))
	return C.SSL_CTX_set_cipher_list((*C.SSL_CTX)(ctx), cStr) == 1
}

// SSL_CTX_set_min_proto_version 设置最低协议版本（经 SSL_CTX_ctrl 规避宏）。
func SSL_CTX_set_min_proto_version(ctx unsafe.Pointer, version int) bool {
	return C.SSL_CTX_ctrl((*C.SSL_CTX)(ctx), C.int(SSLCtrlSetMinProtoVersion),
		C.long(version), nil) >= 0
}

// SSL_CTX_set_max_proto_version 设置最高协议版本（经 SSL_CTX_ctrl 规避宏）。
func SSL_CTX_set_max_proto_version(ctx unsafe.Pointer, version int) bool {
	return C.SSL_CTX_ctrl((*C.SSL_CTX)(ctx), C.int(SSLCtrlSetMaxProtoVersion),
		C.long(version), nil) >= 0
}

// SSL_new 创建新的 SSL。
func SSL_new(ctx unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.SSL_new((*C.SSL_CTX)(ctx)))
}

// SSL_free 释放 SSL。
func SSL_free(ssl unsafe.Pointer) {
	C.SSL_free((*C.SSL)(ssl))
}

// SSL_set_fd 绑定套接字 fd。
func SSL_set_fd(ssl unsafe.Pointer, fd int) bool {
	return C.SSL_set_fd((*C.SSL)(ssl), C.int(fd)) == 1
}

// SSL_connect 发起客户端握手。返回 SSL_read/SSL_write 风格的返回值。
func SSL_connect(ssl unsafe.Pointer) int {
	return int(C.SSL_connect((*C.SSL)(ssl)))
}

// SSL_accept 接受服务端握手。
func SSL_accept(ssl unsafe.Pointer) int {
	return int(C.SSL_accept((*C.SSL)(ssl)))
}

// SSL_shutdown 关闭 TLS 连接。
func SSL_shutdown(ssl unsafe.Pointer) int {
	return int(C.SSL_shutdown((*C.SSL)(ssl)))
}

// SSL_read 读取解密数据。
func SSL_read(ssl unsafe.Pointer, buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	return int(C.SSL_read((*C.SSL)(ssl), unsafe.Pointer(&buf[0]), C.int(len(buf))))
}

// SSL_write 写入待加密数据。
func SSL_write(ssl unsafe.Pointer, buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	return int(C.SSL_write((*C.SSL)(ssl), unsafe.Pointer(&buf[0]), C.int(len(buf))))
}

// SSL_get_error 返回 SSL 错误码。
func SSL_get_error(ssl unsafe.Pointer, ret int) int {
	return int(C.SSL_get_error((*C.SSL)(ssl), C.int(ret)))
}

// SSL_get_version 返回协议版本字符串。
func SSL_get_version(ssl unsafe.Pointer) string {
	return C.GoString(C.SSL_get_version((*C.SSL)(ssl)))
}

// SSL_get_current_cipher_name 返回当前密码套件名。
func SSL_get_current_cipher_name(ssl unsafe.Pointer) string {
	cipher := C.SSL_get_current_cipher((*C.SSL)(ssl))
	if cipher == nil {
		return ""
	}
	return C.GoString(C.SSL_CIPHER_get_name(cipher))
}
