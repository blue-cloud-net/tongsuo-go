package core

import (
	"runtime"
	"sync"
	"unsafe"
)

// Handle 是所有铜锁句柄包装的基类，负责非托管资源（铜锁句柄）的生命周期管理。
//
// 所有权模型：owned 为 true 时本对象拥有底层指针，Close 会调用 closeFunc 释放；
// 外部传入的指针或铜锁内置常量描述符应设 owned=false，避免误释放。
// Close 幂等；使用 runtime.SetFinalizer 作为兜底，但不保证一定执行。
type Handle struct {
	mu        sync.Mutex
	ptr       unsafe.Pointer
	owned     bool
	closed    bool
	closeFunc func(unsafe.Pointer)
}

// NewHandle 创建句柄包装。ptr 为底层指针；owned 表示是否拥有所有权；
// closeFunc 为释放函数（仅 owned 时被调用）。
func NewHandle(ptr unsafe.Pointer, owned bool, closeFunc func(unsafe.Pointer)) *Handle {
	h := &Handle{ptr: ptr, owned: owned, closeFunc: closeFunc}
	if owned && ptr != nil {
		runtime.SetFinalizer(h, (*Handle).finalize)
	}
	return h
}

// Ptr 返回底层指针；句柄关闭后返回 nil。
func (h *Handle) Ptr() unsafe.Pointer {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ptr
}

// IsClosed 报告句柄是否已关闭。
func (h *Handle) IsClosed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

// Close 释放底层资源。幂等，可安全重复调用。
func (h *Handle) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.ptr == nil {
		return nil
	}
	if h.owned && h.closeFunc != nil {
		h.closeFunc(h.ptr)
	}
	h.ptr = nil
	h.closed = true
	runtime.SetFinalizer(h, nil)
	return nil
}

// finalize 是 SetFinalizer 使用的兜底释放入口。
func (h *Handle) finalize() {
	_ = h.Close()
}
