package native

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// X_PKCS7_sign 生成带摘要选项的附带或分离签名。
// X_PKCS7_sign creates an attached or detached signature with a selected digest.
func X_PKCS7_sign(cert, key, extra, input unsafe.Pointer, digest string, detached bool) unsafe.Pointer {
	md := C.CString(digest)
	defer C.free(unsafe.Pointer(md))
	flag := C.int(0)
	if detached {
		flag = 1
	}
	return unsafe.Pointer(C.X_PKCS7_sign((*C.X509)(cert), (*C.EVP_PKEY)(key), (*C.struct_stack_st_X509)(extra), (*C.BIO)(input), md, flag))
}

// X_PKCS7_verify 验证全部签名者，不在此层校验信任。
// X_PKCS7_verify verifies all signatures; trust validation belongs to the API layer.
func X_PKCS7_verify(p7, extra, input, output unsafe.Pointer, supplied bool) bool {
	flag := C.int(0)
	if supplied {
		flag = 1
	}
	return C.X_PKCS7_verify((*C.PKCS7)(p7), (*C.struct_stack_st_X509)(extra), (*C.BIO)(input), flag, (*C.BIO)(output)) == 1
}

// PKCS7_get0_signers 返回借用证书组成的新栈，调用方仅释放栈。
// PKCS7_get0_signers returns a new stack of borrowed certificates; free only the stack.
func PKCS7_get0_signers(p7, extra unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.PKCS7_get0_signers((*C.PKCS7)(p7), (*C.struct_stack_st_X509)(extra), 0))
}

// X_PKCS7_encrypt 生成多接收者 EnvelopedData。
// X_PKCS7_encrypt creates multi-recipient EnvelopedData.
func X_PKCS7_encrypt(recipients, input unsafe.Pointer, cipher string) unsafe.Pointer {
	name := C.CString(cipher)
	defer C.free(unsafe.Pointer(name))
	return unsafe.Pointer(C.X_PKCS7_encrypt((*C.struct_stack_st_X509)(recipients), (*C.BIO)(input), name))
}

// X_PKCS7_decrypt 解密指定接收者的 EnvelopedData。
// X_PKCS7_decrypt decrypts EnvelopedData for a recipient.
func X_PKCS7_decrypt(p7, key, cert, output unsafe.Pointer) bool {
	return C.X_PKCS7_decrypt((*C.PKCS7)(p7), (*C.EVP_PKEY)(key), (*C.X509)(cert), (*C.BIO)(output)) == 1
}

// BIO_ctrl_pending 返回缓冲区待读字节数。
// BIO_ctrl_pending returns the number of buffered bytes available.
func BIO_ctrl_pending(bio unsafe.Pointer) int { return int(C.BIO_ctrl_pending((*C.BIO)(bio))) }
