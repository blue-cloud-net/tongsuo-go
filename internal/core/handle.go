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
//
// Close 幂等；使用 runtime.SetFinalizer 作为兜底，但不保证一定执行。
// 所有访问器（Ptr、IsClosed、Close）使用内部互斥锁，并发安全。
//
// Handle is the base type for all handle wrappers in this package and
// manages the lifecycle of unmanaged Tongsuo pointers.
//
// Ownership model: when owned is true this object owns the underlying
// pointer and Close invokes closeFunc to release it; pointers supplied by
// the caller or built-in Tongsuo constant descriptors (for example
// EVP_CIPHER/EVP_MD) MUST set owned=false to avoid double-freeing
// Tongsuo-owned memory.
//
// Close is idempotent and may be called repeatedly without effect. A
// runtime.SetFinalizer is registered as a safety net but its execution is
// not guaranteed; callers should still invoke Close explicitly. All
// accessors (Ptr, IsClosed, Close) take an internal mutex and are safe
// for concurrent use.
type Handle struct {
	mu        sync.Mutex
	ptr       unsafe.Pointer
	owned     bool
	closed    bool
	closeFunc func(unsafe.Pointer)
}

// NewHandle 创建句柄包装。
//
// ptr 为底层 Tongsuo 指针；owned 表示是否拥有所有权（true 时 Close 会调用 closeFunc 释放）；
// closeFunc 为释放函数，仅在 owned 为 true 时被调用，非 owned 句柄可为 nil。
// owned 为 true 且 ptr 非 nil 时会注册 finalizer 作为兜底；finalizer 在 Close 首次运行时被清除。
//
// NewHandle wraps a raw Tongsuo pointer.
//
// ptr is the underlying Tongsuo pointer; owned reports whether this Handle
// owns the pointer (when true, closeFunc is invoked from Close); closeFunc
// is the release function and is called only when owned is true. It may be
// nil for non-owned handles. When owned is true and ptr is non-nil a
// finalizer is registered as a safety net; the finalizer is cleared the
// first time Close runs.
func NewHandle(ptr unsafe.Pointer, owned bool, closeFunc func(unsafe.Pointer)) *Handle {
	h := &Handle{ptr: ptr, owned: owned, closeFunc: closeFunc}
	if owned && ptr != nil {
		runtime.SetFinalizer(h, (*Handle).finalize)
	}
	return h
}

// Ptr 返回底层指针；句柄关闭后返回 nil。调用并发安全。
//
// Ptr returns the underlying Tongsuo pointer, or nil after Close has been
// called. The call is safe for concurrent use.
func (h *Handle) Ptr() unsafe.Pointer {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ptr
}

// IsClosed 报告句柄是否已关闭。调用并发安全。
//
// IsClosed reports whether the handle has already been released. The call
// is safe for concurrent use.
func (h *Handle) IsClosed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

// Close 释放底层资源。幂等，可安全重复调用。
// 当本 Handle 拥有底层资源（即 owned == true 且 closeFunc != nil）时调用 closeFunc 释放；
// 对非 owned 句柄，Close 为 no-op，仍返回 nil。Close 返回后 Ptr 报告 nil，
// 基于本 Handle 的所有包装器在后续操作上将返回 "context closed" 错误。
//
// Close releases the underlying unmanaged resource when this Handle owns
// it (i.e. owned == true and closeFunc != nil). The call is idempotent and
// safe to invoke multiple times; for non-owned handles it is a no-op that
// still returns nil. After Close returns, Ptr reports nil and all other
// wrappers built on top of this Handle will return "context closed"
// errors on subsequent operations.
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
//
// finalize is the fallback release entry used by Runtime.SetFinalizer; it
// invokes Close and ignores any returned error.
func (h *Handle) finalize() {
	_ = h.Close()
}
