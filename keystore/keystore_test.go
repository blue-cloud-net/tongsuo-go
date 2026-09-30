package keystore_test

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/keystore"
	"github.com/blue-cloud-net/tongsuo-go/sym"
)

// testDecoder 是本包测试用的 PEM 解码器：按块类型分派到 sym / asym。
//
// testDecoder is the PEM decoder used by this package's tests: it dispatches
// on the PEM block type to sym / asym.
func testDecoder(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch {
	case block.Type == "SYMMETRIC KEY":
		return sym.ParseSymmetricKey(pemBytes)
	case strings.HasSuffix(block.Type, "PUBLIC KEY"):
		return asym.LoadPublicKeyPEM(pemBytes)
	default:
		return asym.LoadPrivateKeyPEM(pemBytes)
	}
}

// newSymKey 生成一把 SM4 对称密钥。
//
// newSymKey generates an SM4 symmetric key.
func newSymKey(t *testing.T) *sym.SM4Key {
	t.Helper()
	k, err := sym.GenerateSymmetricKey(sym.AlgSM4)
	if err != nil {
		t.Fatal(err)
	}
	sm4, ok := k.(*sym.SM4Key)
	if !ok {
		t.Fatalf("GenerateSymmetricKey(SM4) returned %T", k)
	}
	return sm4
}

// newECKey 生成一把 P-256 非对称私钥。
//
// newECKey generates a P-256 asymmetric private key.
func newECKey(t *testing.T) asym.PrivateKey {
	t.Helper()
	k, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestNewHandle 验证 NewHandle 的参数校验与字段默认值、算法自动填充。
func TestNewHandle(t *testing.T) {
	if _, err := keystore.NewHandle("", newSymKey(t)); err == nil {
		t.Error("空 id 应报错")
	}
	if _, err := keystore.NewHandle("k1", nil); err == nil {
		t.Error("nil key 应报错")
	}

	h, err := keystore.NewHandle("k1", newSymKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != "k1" {
		t.Errorf("ID = %q, want k1", h.ID)
	}
	if h.Algorithm != string(sym.AlgSM4) {
		t.Errorf("Algorithm = %q, want %q", h.Algorithm, sym.AlgSM4)
	}
	if h.Version != 1 {
		t.Errorf("Version = %d, want 1", h.Version)
	}
	if h.Generation != 0 {
		t.Errorf("Generation = %d, want 0", h.Generation)
	}
	if h.CreatedAt.IsZero() {
		t.Error("CreatedAt 未填充")
	}

	// 非对称密钥同样自动填充算法名
	ah, err := keystore.NewHandle("a1", newECKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if ah.Algorithm != string(asym.AlgEC) {
		t.Errorf("Algorithm = %q, want %q", ah.Algorithm, asym.AlgEC)
	}
	if err := ah.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestAlgorithmNameUnsupported 验证无 Algorithm() 方法的密钥不会导致 panic，只留空算法名。
func TestAlgorithmNameUnsupported(t *testing.T) {
	h, err := keystore.NewHandle("raw", struct{ N int }{N: 1})
	if err != nil {
		t.Fatal(err)
	}
	if h.Algorithm != "" {
		t.Errorf("Algorithm = %q, want empty", h.Algorithm)
	}
	// 该类型也无法序列化
	if _, err := h.MarshalJSON(); !errors.Is(err, keystore.ErrUnsupported) {
		t.Errorf("MarshalJSON err = %v, want ErrUnsupported", err)
	}
}

// TestCloseIdempotent 验证 Close 幂等，且对称密钥为 no-op。
func TestCloseIdempotent(t *testing.T) {
	var nilHandle *keystore.Handle
	if err := nilHandle.Close(); err != nil {
		t.Errorf("nil handle Close: %v", err)
	}
	if err := keystore.Close(nil); err != nil {
		t.Errorf("Close(nil): %v", err)
	}
	if err := keystore.Close(&keystore.Handle{}); err != nil {
		t.Errorf("Close(empty): %v", err)
	}

	// 对称密钥无原生句柄
	sh := &keystore.Handle{ID: "s", Key: newSymKey(t)}
	for i := 0; i < 3; i++ {
		if err := sh.Close(); err != nil {
			t.Fatalf("对称密钥 Close #%d: %v", i, err)
		}
	}

	// 非对称密钥：Close 后可重复调用
	priv := newECKey(t)
	ah := &keystore.Handle{ID: "a", Key: priv}
	if err := ah.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := ah.Close(); err != nil {
		t.Fatalf("重复 Close: %v", err)
	}
	// 句柄已释放，再用应报错
	if _, err := priv.MarshalPrivateKeyPEM(); err == nil {
		t.Error("Close 后仍可导出私钥 PEM，句柄未真正释放")
	}
}

// TestMemoryStoreCRUD 验证 Get / Put / Delete / List 与 ErrNotFound。
func TestMemoryStoreCRUD(t *testing.T) {
	s := keystore.NewMemoryStore()

	if _, err := s.Get("missing"); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("Get(missing) err = %v, want ErrNotFound", err)
	}
	if err := s.Delete("missing"); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("Delete(missing) err = %v, want ErrNotFound", err)
	}
	if _, err := s.History("missing"); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("History(missing) err = %v, want ErrNotFound", err)
	}
	if err := s.Put(nil); err == nil {
		t.Error("Put(nil) 应报错")
	}
	if err := s.Put(&keystore.Handle{}); err == nil {
		t.Error("Put(空 ID) 应报错")
	}

	// 逆序插入，List 应按 ID 排序
	for _, id := range []string{"c", "a", "b"} {
		h, err := keystore.NewHandle(id, newSymKey(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(h); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("List len = %d, want 3", len(list))
	}
	for i, want := range []string{"a", "b", "c"} {
		if list[i].ID != want {
			t.Errorf("List[%d].ID = %q, want %q", i, list[i].ID, want)
		}
	}

	got, err := s.Get("b")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "b" {
		t.Errorf("Get(b).ID = %q", got.ID)
	}

	if err := s.Delete("b"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("b"); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("删除后 Get err = %v, want ErrNotFound", err)
	}
	// 刚写入但从未轮转的 ID：历史为空且不报错
	if hist, err := s.History("c"); err != nil || len(hist) != 0 {
		t.Errorf("History(c) = %v, %v; want empty, nil", hist, err)
	}
	// 被删除且从未归档的 ID：键与历史都无记录 → ErrNotFound
	if hist, err := s.History("b"); !errors.Is(err, keystore.ErrNotFound) || hist != nil {
		t.Errorf("History(b) = %v, %v; want nil, ErrNotFound", hist, err)
	}
}

// TestPutOverwriteArchives 验证同 ID 覆盖会把旧 Handle 归档。
func TestPutOverwriteArchives(t *testing.T) {
	s := keystore.NewMemoryStore()
	first, err := keystore.NewHandle("k", newSymKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(first); err != nil {
		t.Fatal(err)
	}
	second, err := keystore.NewHandle("k", newSymKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(second); err != nil {
		t.Fatal(err)
	}

	cur, err := s.Get("k")
	if err != nil {
		t.Fatal(err)
	}
	if cur != second {
		t.Error("Get 应返回后写入的条目")
	}
	hist, err := s.History("k")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0] != first {
		t.Errorf("History = %v, want [first]", hist)
	}
}

// TestRotate 验证轮转的版本递增、别名 / 代数保留与历史归档顺序。
func TestRotate(t *testing.T) {
	s := keystore.NewMemoryStore()
	h, err := keystore.NewHandle("k", newSymKey(t))
	if err != nil {
		t.Fatal(err)
	}
	h.Alias = "primary"
	h.Generation = 7
	if err := s.Put(h); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Rotate("k", nil); err == nil {
		t.Error("Rotate(nil key) 应报错")
	}
	if _, err := s.Rotate("missing", newSymKey(t)); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("Rotate(missing) err = %v, want ErrNotFound", err)
	}

	prev := h
	for v := uint32(2); v <= 4; v++ {
		next, err := s.Rotate("k", newSymKey(t))
		if err != nil {
			t.Fatal(err)
		}
		if next.Version != v {
			t.Errorf("Version = %d, want %d", next.Version, v)
		}
		if next.Alias != "primary" {
			t.Errorf("Alias = %q, want primary", next.Alias)
		}
		if next.Generation != 7 {
			t.Errorf("Generation = %d, want 7", next.Generation)
		}
		if next.Algorithm != string(sym.AlgSM4) {
			t.Errorf("Algorithm = %q, want %q", next.Algorithm, sym.AlgSM4)
		}
		if next.CreatedAt.Before(prev.CreatedAt) {
			t.Error("CreatedAt 应随轮转推进")
		}
		prev = next
	}

	cur, err := s.Get("k")
	if err != nil {
		t.Fatal(err)
	}
	if cur.Version != 4 {
		t.Errorf("当前条目 Version = %d, want 4", cur.Version)
	}
	hist, err := s.History("k")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 3 {
		t.Fatalf("History len = %d, want 3", len(hist))
	}
	for i, want := range []uint32{1, 2, 3} {
		if hist[i].Version != want {
			t.Errorf("History[%d].Version = %d, want %d", i, hist[i].Version, want)
		}
	}
}

// TestMarshalJSONRoundTrip 验证 Handle ↔ JSON 往返（对称密钥与非对称私钥 / 公钥）。
func TestMarshalJSONRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		key  func(*testing.T) any
	}{
		{"SM4", func(t *testing.T) any { return newSymKey(t) }},
		{"EC-private", func(t *testing.T) any { return newECKey(t) }},
		{"EC-public", func(t *testing.T) any { return newECKey(t).Public() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := keystore.NewHandle("k-"+tc.name, tc.key(t))
			if err != nil {
				t.Fatal(err)
			}
			h.Alias = "alias"
			h.Generation = 3

			data, err := json.Marshal(h)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !strings.Contains(string(data), "key_pem") {
				t.Errorf("JSON 未内嵌 key_pem: %s", data)
			}
			// 内嵌 PEM 应为明文（安全提示已声明）：块类型可辨识
			block, _ := pem.Decode([]byte(extractKeyPEM(t, data)))
			if block == nil {
				t.Fatal("key_pem 不是合法 PEM")
			}

			back, err := keystore.UnmarshalHandle(data, testDecoder)
			if err != nil {
				t.Fatalf("UnmarshalHandle: %v", err)
			}
			if back.ID != h.ID || back.Alias != h.Alias || back.Algorithm != h.Algorithm ||
				back.Version != h.Version || back.Generation != h.Generation {
				t.Errorf("元数据往返不一致：%+v vs %+v", back, h)
			}
			if !back.CreatedAt.Equal(h.CreatedAt) {
				t.Errorf("CreatedAt 往返不一致：%v vs %v", back.CreatedAt, h.CreatedAt)
			}
			if back.Key == nil {
				t.Fatal("Key 未还原")
			}
			// 重新序列化应与原 JSON 等价（PEM 编码确定）
			again, err := json.Marshal(back)
			if err != nil {
				t.Fatal(err)
			}
			if string(again) != string(data) {
				t.Errorf("二次序列化不等价\n got %s\nwant %s", again, data)
			}
		})
	}
}

// extractKeyPEM 从 Handle 的 JSON 中取出 key_pem 字段。
//
// extractKeyPEM pulls the key_pem field out of a Handle's JSON.
func extractKeyPEM(t *testing.T, data []byte) string {
	t.Helper()
	var j struct {
		KeyPEM string `json:"key_pem"`
	}
	if err := json.Unmarshal(data, &j); err != nil {
		t.Fatal(err)
	}
	return j.KeyPEM
}

// TestUnmarshalRequiresDecoder 验证未注入解码器时返回 ErrNoDecoder。
func TestUnmarshalRequiresDecoder(t *testing.T) {
	h, err := keystore.NewHandle("k", newSymKey(t))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}

	// 直接 json.Unmarshal 到空 Handle：缺少解码器
	var plain keystore.Handle
	if err := json.Unmarshal(data, &plain); !errors.Is(err, keystore.ErrNoDecoder) {
		t.Errorf("json.Unmarshal err = %v, want ErrNoDecoder", err)
	}

	// 经 SetDecoder 注入后可成功
	injected := (&keystore.Handle{}).SetDecoder(testDecoder)
	if err := json.Unmarshal(data, injected); err != nil {
		t.Fatalf("注入解码器后 json.Unmarshal: %v", err)
	}
	if injected.Key == nil || injected.ID != "k" {
		t.Errorf("还原结果不完整：%+v", injected)
	}

	// UnmarshalHandle 的 nil 解码器守卫
	if _, err := keystore.UnmarshalHandle(data, nil); !errors.Is(err, keystore.ErrNoDecoder) {
		t.Errorf("UnmarshalHandle(nil decoder) err = %v, want ErrNoDecoder", err)
	}
	// 非法 JSON
	if _, err := keystore.UnmarshalHandle([]byte("{"), testDecoder); err == nil {
		t.Error("非法 JSON 应报错")
	}
	// 解码器失败
	if _, err := keystore.UnmarshalHandle(data, func([]byte) (any, error) {
		return nil, errors.New("boom")
	}); err == nil {
		t.Error("解码器失败应上抛")
	}
}

// TestMigrationParityWithKeyPackage 验证 keystore 覆盖 key 包 Handle/Store 的既有语义。
// 目的是在 commit 21 删除 key 包之前锁定行为等价。
func TestMigrationParityWithKeyPackage(t *testing.T) {
	s := keystore.NewMemoryStore()
	h, err := keystore.NewHandle("id-1", newSymKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(h); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get("id-1"); err != nil || got != h {
		t.Fatalf("Get = %v, %v", got, err)
	}
	rotated, err := s.Rotate("id-1", newSymKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Version != h.Version+1 {
		t.Errorf("Version = %d, want %d", rotated.Version, h.Version+1)
	}
	if err := s.Delete("id-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("id-1"); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// TestMemoryStoreConcurrent 验证并发读写不产生数据竞争（配合 -race）。
func TestMemoryStoreConcurrent(t *testing.T) {
	s := keystore.NewMemoryStore()
	const workers = 8
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			id := fmt.Sprintf("k-%d", w)
			for i := 0; i < 20; i++ {
				h, err := keystore.NewHandle(id, newSymKey(t))
				if err != nil {
					t.Error(err)
					return
				}
				if err := s.Put(h); err != nil {
					t.Error(err)
					return
				}
				if _, err := s.Get(id); err != nil {
					t.Error(err)
					return
				}
				if _, err := s.List(); err != nil {
					t.Error(err)
					return
				}
				if _, err := s.History(id); err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != workers {
		t.Errorf("List len = %d, want %d", len(list), workers)
	}
}
