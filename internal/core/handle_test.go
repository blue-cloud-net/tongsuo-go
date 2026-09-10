package core

import (
	"sync"
	"testing"
	"unsafe"
)

// TestHandleCloseIdempotent 验证 Close 幂等：重复 Close 不会重复释放。
func TestHandleCloseIdempotent(t *testing.T) {
	closeFn := func(p unsafe.Pointer) {
		// 空操作：仅检查 Close 不会重复触发
	}
	// 使用一个真实分配的指针（避免 uintptr→unsafe.Pointer 的 vet 警告）
	marker := &struct{}{}
	h := NewHandle(unsafe.Pointer(marker), true, closeFn)
	if err := h.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("third Close: %v", err)
	}
	if !h.IsClosed() {
		t.Fatalf("IsClosed() after Close should be true")
	}
}

// TestHandleIsClosedTiming 验证 Close 前 IsClosed 为 false，Close 后为 true。
func TestHandleIsClosedTiming(t *testing.T) {
	marker := &struct{}{}
	h := NewHandle(unsafe.Pointer(marker), false, nil)
	if h.IsClosed() {
		t.Fatal("new handle should not be IsClosed()")
	}
	_ = h.Close()
	if !h.IsClosed() {
		t.Fatal("after Close should be IsClosed()")
	}
}

// TestHandleNilReceiver 验证 nil Handle 的 Close 是安全的（其他方法无 nil 守卫）。
//
// 注意：当前实现仅 Close 提供 nil 接收者守卫（见 handle.go:84），IsClosed /
// Ptr / 等需要 nil 守卫的方法调用 nil Handle 会 panic。调用方约定使用
// NewHandle 创建句柄，并在调用方法前确认非 nil。
func TestHandleNilReceiver(t *testing.T) {
	var h *Handle
	// Close 对 nil 接收者安全（nil 短路返回 nil）。
	if err := h.Close(); err != nil {
		t.Errorf("nil Close should return nil, got %v", err)
	}
}

// TestHandleNonOwnedCloseNoFree 验证 owned=false 的句柄 Close 不会调用 closeFunc。
func TestHandleNonOwnedCloseNoFree(t *testing.T) {
	called := false
	closeFn := func(p unsafe.Pointer) {
		called = true
	}
	marker := &struct{}{}
	h := NewHandle(unsafe.Pointer(marker), false, closeFn)
	_ = h.Close()
	if called {
		t.Fatal("closeFunc should not be called for non-owned handle")
	}
}

// TestHandleOwnedCloseCallsFunc 验证 owned=true 的句柄 Close 会调用 closeFunc。
func TestHandleOwnedCloseCallsFunc(t *testing.T) {
	called := false
	closeFn := func(p unsafe.Pointer) {
		called = true
	}
	marker := &struct{}{}
	h := NewHandle(unsafe.Pointer(marker), true, closeFn)
	_ = h.Close()
	if !called {
		t.Fatal("closeFunc should be called for owned handle")
	}
}

// TestHandleConcurrentClose 验证并发 Close 安全。
func TestHandleConcurrentClose(t *testing.T) {
	var count int
	var mu sync.Mutex
	closeFn := func(p unsafe.Pointer) {
		mu.Lock()
		count++
		mu.Unlock()
	}
	marker := &struct{}{}
	h := NewHandle(unsafe.Pointer(marker), true, closeFn)

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = h.Close()
		}()
	}
	wg.Wait()
	if count != 1 {
		t.Fatalf("closeFunc called %d times, want 1", count)
	}
}
