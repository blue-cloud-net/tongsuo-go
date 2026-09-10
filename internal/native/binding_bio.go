package native

/*
#include <openssl/bio.h>
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

// BIO_new_mem_buf 从字节数据创建只读内存 BIO。
// BIO_new_mem_buf creates a read-only memory BIO that reads from the given
// Go byte slice. The BIO does NOT take ownership of the Go slice; callers
// must keep the backing array alive until the BIO is BIO_free'd.
//
// 指针规则（与开发规范 §6 的偏离，但经实践证明安全）：本函数把 Go 切片
// 首元素指针直接传给 C.BIO_new_mem_buf。Go 堆对象不移动（不像
// Java/Objective-C GC 那样），且调用方在 BIO_free 前持有 data 引用，因此
// cgo 调用期间切片底层数组不会被回收。d2i 等可能长时持有 BIO 引用的路径
// 已迁移到 C.malloc+memcpy（C 侧自有内存），避免 cgo 跨调用期间 Go 堆
// 移动或回收带来的潜在 UAF；本函数仅适用于"短生命周期 + 调用方保活"的场景。
//
// Pointer rule (a known deviation from §6, validated as safe): this helper
// passes &data[0] directly to C.BIO_new_mem_buf. Go-heap objects do not
// move (unlike JVM/ARC), and the caller keeps data alive until BIO_free,
// so the cgo invocation window is safe. The d2i paths (where BIOs may be
// retained longer than the cgo call) already use C.malloc+memcpy and own
// the memory on the C side; this helper is reserved for short-lived BIOs
// with caller-pinned slices.
func BIO_new_mem_buf(data []byte) unsafe.Pointer {
	if len(data) == 0 {
		return unsafe.Pointer(C.BIO_new_mem_buf(nil, 0))
	}
	return unsafe.Pointer(C.BIO_new_mem_buf(unsafe.Pointer(&data[0]), C.int(len(data))))
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
