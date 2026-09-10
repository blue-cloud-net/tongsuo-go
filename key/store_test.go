package key_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/key"
)

func newTestHandle(t *testing.T, id string, k key.Key) *key.Handle {
	t.Helper()
	h, err := key.NewHandle(id, k)
	if err != nil {
		t.Fatalf("NewHandle(%s): %v", id, err)
	}
	return h
}

func TestNewHandleValidation(t *testing.T) {
	sk, err := key.GenerateSymmetricKey(key.AlgSM4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.NewHandle("", sk); err == nil {
		t.Error("empty id: want error")
	}
	if _, err := key.NewHandle("k1", nil); err == nil {
		t.Error("nil key: want error")
	}
	h, err := key.NewHandle("k1", sk)
	if err != nil {
		t.Fatal(err)
	}
	if h.Version != 1 {
		t.Errorf("Version = %d, want 1", h.Version)
	}
	if h.Algorithm != key.AlgSM4 {
		t.Errorf("Algorithm = %s, want SM4", h.Algorithm)
	}
	if h.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestMemoryStoreCRUD(t *testing.T) {
	s := key.NewMemoryStore()
	sk, err := key.GenerateSymmetricKey(key.AlgAES256)
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandle(t, "k1", sk)

	if _, err := s.Get("k1"); !errors.Is(err, key.ErrNotFound) {
		t.Fatalf("Get(missing) err = %v, want ErrNotFound", err)
	}
	if err := s.Put(h); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get("k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != h {
		t.Error("Get returned a different handle")
	}
	// 覆盖写进入历史
	sk2, err := key.GenerateSymmetricKey(key.AlgAES256)
	if err != nil {
		t.Fatal(err)
	}
	h2 := newTestHandle(t, "k1", sk2)
	if err := s.Put(h2); err != nil {
		t.Fatalf("Put(overwrite): %v", err)
	}
	hist, err := s.History("k1")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 1 || hist[0] != h {
		t.Errorf("History = %d entries, want [old handle]", len(hist))
	}
	// 列表
	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "k1" {
		t.Errorf("List = %+v, want single k1", entries)
	}
	// 删除
	if err := s.Delete("k1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("k1"); !errors.Is(err, key.ErrNotFound) {
		t.Error("Get after Delete: want ErrNotFound")
	}
	if err := s.Delete("k1"); !errors.Is(err, key.ErrNotFound) {
		t.Error("Delete(missing): want ErrNotFound")
	}
}

func TestMemoryStorePutErrors(t *testing.T) {
	s := key.NewMemoryStore()
	if err := s.Put(nil); err == nil {
		t.Error("Put(nil): want error")
	}
	sk, _ := key.GenerateSymmetricKey(key.AlgSM4)
	h, _ := key.NewHandle("", sk)
	if err := s.Put(h); err == nil {
		t.Error("Put(empty id): want error")
	}
}

func TestMemoryStoreRotate(t *testing.T) {
	s := key.NewMemoryStore()
	orig, err := key.GenerateSymmetricKey(key.AlgAES128)
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandle(t, "rot", orig)
	if err := s.Put(h); err != nil {
		t.Fatal(err)
	}

	rot, err := key.GenerateSymmetricKey(key.AlgAES128)
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.Rotate("rot", rot)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if next.Version != 2 {
		t.Errorf("rotated Version = %d, want 2", next.Version)
	}
	// 当前条目指向新密钥
	cur, err := s.Get("rot")
	if err != nil {
		t.Fatal(err)
	}
	if !cur.Key.Equal(rot) {
		t.Error("current key should equal rotated key")
	}
	// 旧版本进入历史
	hist, err := s.History("rot")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].Version != 1 {
		t.Errorf("History after rotate = %+v, want [v1]", hist)
	}
	// 再次轮转
	rot2, err := key.GenerateSymmetricKey(key.AlgAES128)
	if err != nil {
		t.Fatal(err)
	}
	next2, err := s.Rotate("rot", rot2)
	if err != nil {
		t.Fatal(err)
	}
	if next2.Version != 3 {
		t.Errorf("second rotate Version = %d, want 3", next2.Version)
	}
	if _, err := s.Rotate("missing", rot2); !errors.Is(err, key.ErrNotFound) {
		t.Error("Rotate(missing): want ErrNotFound")
	}
	if _, err := s.Rotate("rot", nil); err == nil {
		t.Error("Rotate(nil key): want error")
	}
}

func TestMemoryStoreConcurrent(t *testing.T) {
	s := key.NewMemoryStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			sk, err := key.GenerateSymmetricKey(key.AlgAES256)
			if err != nil {
				t.Errorf("generate: %v", err)
				return
			}
			h, err := key.NewHandle(fmt.Sprintf("k%d", n%5), sk)
			if err != nil {
				t.Errorf("handle: %v", err)
				return
			}
			_ = s.Put(h)
			_, _ = s.Get(h.ID)
			_, _ = s.List()
		}(i)
	}
	wg.Wait()
	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one entry")
	}
}

func TestHandleJSONRoundTrip(t *testing.T) {
	// 对称密钥
	sk, err := key.GenerateSymmetricKey(key.AlgSM4)
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandle(t, "sym", sk)
	h.Alias = "data-key"
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var got key.Handle
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if got.ID != "sym" || got.Alias != "data-key" || got.Version != 1 {
		t.Errorf("metadata mismatch: %+v", got)
	}
	if !got.Key.Equal(sk) {
		t.Error("symmetric key not restored")
	}

	// RSA 公钥
	priv, err := key.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	hp := newTestHandle(t, "rsa-pub", pub)
	bp, err := json.Marshal(hp)
	if err != nil {
		t.Fatalf("MarshalJSON(public): %v", err)
	}
	var gotPub key.Handle
	if err := json.Unmarshal(bp, &gotPub); err != nil {
		t.Fatalf("UnmarshalJSON(public): %v", err)
	}
	if !gotPub.Key.Equal(pub) {
		t.Error("public key not restored")
	}

	// RSA 私钥(未加密 PKCS#8 明文内嵌,仅受信场景演示)
	hpv := newTestHandle(t, "rsa-priv", priv)
	bpv, err := json.Marshal(hpv)
	if err != nil {
		t.Fatalf("MarshalJSON(private): %v", err)
	}
	var gotPriv key.Handle
	if err := json.Unmarshal(bpv, &gotPriv); err != nil {
		t.Fatalf("UnmarshalJSON(private): %v", err)
	}
	if !gotPriv.Key.Equal(priv) {
		t.Error("private key not restored")
	}
}

func TestHandleClose(t *testing.T) {
	sk, err := key.GenerateSymmetricKey(key.AlgSM4)
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandle(t, "k", sk)
	if err := h.Close(); err != nil {
		t.Fatalf("Handle.Close(symmetric): %v", err)
	}
	priv, err := key.GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	hp := newTestHandle(t, "k2", priv)
	if err := hp.Close(); err != nil {
		t.Fatalf("Handle.Close(asymmetric): %v", err)
	}
	if err := hp.Close(); err != nil {
		t.Fatalf("second Handle.Close: %v, want nil", err)
	}
	var nilH *key.Handle
	if err := nilH.Close(); err != nil {
		t.Fatalf("nil Handle.Close: %v, want nil", err)
	}
}
