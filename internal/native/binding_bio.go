package native

/*
#include <openssl/bio.h>
*/
import "C"
import "unsafe"

// BIO_s_mem 返回内存 BIO 方法。
//
// BIO_s_mem returns the in-memory BIO_METHOD used to build memory BIOs.
func BIO_s_mem() unsafe.Pointer {
	return unsafe.Pointer(C.BIO_s_mem())
}

// BIO_new 使用指定方法创建 BIO。
//
// BIO_new allocates and returns a new BIO that uses the given BIO_METHOD.
func BIO_new(method unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.BIO_new((*C.BIO_METHOD)(method)))
}

// BIO_new_mem_buf 从字节数据创建只读内存 BIO。
//
// BIO_new_mem_buf creates a read-only memory BIO that reads from the given
// Go byte slice. The BIO does NOT take ownership of the Go slice; callers
// must keep the backing array alive until the BIO is BIO_free'd.
func BIO_new_mem_buf(data []byte) unsafe.Pointer {
	if len(data) == 0 {
		return unsafe.Pointer(C.BIO_new_mem_buf(nil, 0))
	}
	return unsafe.Pointer(C.BIO_new_mem_buf(unsafe.Pointer(&data[0]), C.int(len(data))))
}

// BIO_free 释放 BIO。
//
// BIO_free releases the BIO. If bio is NULL this is a no-op; once freed the
// pointer must not be used again.
func BIO_free(bio unsafe.Pointer) {
	C.BIO_free((*C.BIO)(bio))
}

// BIO_read 从 BIO 读取至多 len(buf) 字节，返回实际读取数。
//
// BIO_read reads up to len(buf) bytes from bio into buf and returns the
// number of bytes actually transferred. -1 indicates an error (consult the
// OpenSSL error queue); 0 means EOF or no data.
func BIO_read(bio unsafe.Pointer, buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	return int(C.BIO_read((*C.BIO)(bio), unsafe.Pointer(&buf[0]), C.int(len(buf))))
}

// BIO_write 向 BIO 写入至多 len(data) 字节，返回实际写入数。
//
// BIO_write writes up to len(data) bytes from data to bio and returns the
// number of bytes actually written. -1 indicates an error (consult the
// OpenSSL error queue).
func BIO_write(bio unsafe.Pointer, data []byte) int {
	if len(data) == 0 {
		return 0
	}
	return int(C.BIO_write((*C.BIO)(bio), unsafe.Pointer(&data[0]), C.int(len(data))))
}
