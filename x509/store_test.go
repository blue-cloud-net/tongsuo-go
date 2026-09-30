package x509_test

import (
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// TestStoreCloseIdempotent 验证 Store.Close 的幂等性与 nil 安全性：重复释放、
// 对 nil 接收者释放都必须返回 nil（对应 docs/issues/2026-09-24/P1010）。
//
// TestStoreCloseIdempotent verifies that Store.Close is idempotent and safe on a
// nil receiver: repeated releases and a release through a nil pointer must both
// return nil (see docs/issues/2026-09-24/P1010).
func TestStoreCloseIdempotent(t *testing.T) {
	store := x509.NewStore()
	if err := store.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	var nilStore *x509.Store
	if err := nilStore.Close(); err != nil {
		t.Fatalf("nil Store.Close: %v", err)
	}
}

// TestStoreUseAfterClose 验证释放后再使用返回明确错误，而不是 panic 或静默成功。
//
// 用例自带正向对照：同一批调用在 Close 之前必须成功，否则本用例没有牙齿。
//
// TestStoreUseAfterClose verifies that using a released store returns an explicit
// error instead of panicking or silently succeeding.
//
// The test carries its own positive control: the same calls must succeed before
// Close, otherwise it would have no teeth.
func TestStoreUseAfterClose(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatalf("GenerateSM2: %v", err)
	}
	defer func() { _ = asym.Close(priv) }()

	now := time.Now()
	cert, err := x509.CreateSelfSigned(x509.NewName().Add("CN", "store-close.dev"), 7,
		now.Add(-time.Minute), now.Add(time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatalf("CreateSelfSigned: %v", err)
	}
	defer func() { _ = cert.Close() }()

	store := x509.NewStore()

	// 正向对照：未释放时「加信任锚 + 链验证」全流程可用。
	if err := store.AddCert(cert); err != nil {
		t.Fatalf("AddCert before Close: %v", err)
	}
	if _, err := x509.ChainVerify(cert, store, nil); err != nil {
		t.Fatalf("ChainVerify before Close: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 释放后：core 层标记已关闭，各入口给出明确错误。
	if err := store.AddCert(cert); err == nil || !strings.Contains(err.Error(), "store") {
		t.Errorf("AddCert after Close = %v, want a store-closed error", err)
	}
	if err := store.SetFlags(0); err == nil {
		t.Error("SetFlags after Close = nil, want error")
	}
	if err := store.SetTime(now); err == nil {
		t.Error("SetTime after Close = nil, want error")
	}
	if _, err := x509.ChainVerify(cert, store, nil); err == nil {
		t.Error("ChainVerify after Close = nil, want error")
	}
}
