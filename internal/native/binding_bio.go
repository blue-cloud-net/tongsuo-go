package native

/*
#include <openssl/bio.h>
*/
import "C"
import "unsafe"

// BIO_s_mem 返回内存 BIO 方法。
func BIO_s_mem() unsafe.Pointer {
	return unsafe.Pointer(C.BIO_s_mem())
}

// BIO_new 使用指定方法创建 BIO。
func BIO_new(method unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.BIO_new((*C.BIO_METHOD)(method)))
}

// BIO_new_mem_buf 从字节数据创建只读内存 BIO。
func BIO_new_mem_buf(data []byte) unsafe.Pointer {
	if len(data) == 0 {
		return unsafe.Pointer(C.BIO_new_mem_buf(nil, 0))
	}
	return unsafe.Pointer(C.BIO_new_mem_buf(unsafe.Pointer(&data[0]), C.int(len(data))))
}

// BIO_free 释放 BIO。
func BIO_free(bio unsafe.Pointer) {
	C.BIO_free((*C.BIO)(bio))
}

// BIO_read 从 BIO 读取至多 len(buf) 字节，返回实际读取数。
func BIO_read(bio unsafe.Pointer, buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	return int(C.BIO_read((*C.BIO)(bio), unsafe.Pointer(&buf[0]), C.int(len(buf))))
}
