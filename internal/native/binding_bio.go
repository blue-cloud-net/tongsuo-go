package native

/*
#include <openssl/bio.h>

static BIO *X_BIO_new_input(const void *data, size_t len) {
    BIO *bio = BIO_new(BIO_s_secmem());
    size_t written = 0;
    if (bio == NULL)
        return NULL;
    if (BIO_set_mem_eof_return(bio, 0) <= 0 ||
        BIO_write_ex(bio, data, len, &written) != 1 || written != len) {
        BIO_free(bio);
        return NULL;
    }
    return bio;
}
*/
import "C"
import "unsafe"

// BIO_s_mem 返回内存 BIO 方法。
// BIO_s_mem returns the in-memory BIO_METHOD used to build memory BIOs.
func BIO_s_mem() unsafe.Pointer {
	return unsafe.Pointer(C.BIO_s_mem())
}

// BIO_new 使用指定方法创建 BIO。
// BIO_new allocates and returns a new BIO that uses the given BIO_METHOD.
func BIO_new(method unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.BIO_new((*C.BIO_METHOD)(method)))
}

// X_BIO_new_input 将数据复制到由 BIO 持有的原生缓冲区。
//
// X_BIO_new_input copies data into a native buffer owned by the BIO.
func X_BIO_new_input(data []byte) unsafe.Pointer {
	if len(data) == 0 {
		return nil
	}
	return unsafe.Pointer(C.X_BIO_new_input(unsafe.Pointer(&data[0]), C.size_t(len(data))))
}

// BIO_free 释放 BIO。
// BIO_free releases the BIO. If bio is NULL this is a no-op; once freed the
// pointer must not be used again.
func BIO_free(bio unsafe.Pointer) {
	C.BIO_free((*C.BIO)(bio))
}

// BIO_read 从 BIO 读取至多 len(buf) 字节，返回实际读取数。
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
// BIO_write writes up to len(data) bytes from data to bio and returns the
// number of bytes actually written. -1 indicates an error (consult the
// OpenSSL error queue).
func BIO_write(bio unsafe.Pointer, data []byte) int {
	if len(data) == 0 {
		return 0
	}
	return int(C.BIO_write((*C.BIO)(bio), unsafe.Pointer(&data[0]), C.int(len(data))))
}
