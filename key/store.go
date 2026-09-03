package key

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Store 是密钥存储的抽象接口,提供按 ID 的增删查、枚举与轮转。
//
// 实现方负责自身的并发与持久化语义;本包提供线程安全的 MemoryStore 供进程内
// 使用。Store 不拥有密钥的所有权:删除或轮转归档的 Handle 不会自动 Close,
// 调用方须对不再使用的 Handle 显式调用 Close 以释放底层句柄。
//
// Store is the abstract interface of a key store, offering ID-based CRUD,
// enumeration and rotation.
//
// Implementations own their concurrency and persistence semantics; this
// package ships a thread-safe MemoryStore for in-process use. A Store does
// not take ownership of keys: handles that are deleted or archived by
// rotation are not automatically closed — callers must explicitly Close
// handles they no longer need to release the underlying key handles.
type Store interface {
	// Get 按 ID 返回密钥条目;不存在时返回 ErrNotFound。
	//
	// Get returns the entry with the given ID, or ErrNotFound when absent.
	Get(id string) (*Handle, error)
	// Put 存入(upsert)密钥条目;h 或 h.ID 为 nil/空时返回错误。
	//
	// Put stores (upserts) the entry; a nil h or an empty h.ID returns an error.
	Put(h *Handle) error
	// Delete 删除指定 ID 的条目;不存在时返回 ErrNotFound。
	//
	// Delete removes the entry with the given ID, or returns ErrNotFound
	// when absent.
	Delete(id string) error
	// List 返回全部条目(实现方自定顺序,MemoryStore 按 ID 排序)。
	//
	// List returns all entries (ordering is implementation-defined;
	// MemoryStore sorts by ID).
	List() ([]*Handle, error)
	// Rotate 用 newKey 轮转指定 ID 的条目:生成 Version+1 的新 Handle,并将旧
	// Handle 归档。ID 不存在时返回 ErrNotFound。
	//
	// Rotate rotates the entry with the given ID to newKey: it produces a
	// new Handle with Version+1 and archives the old handle. ErrNotFound is
	// returned when the ID does not exist.
	Rotate(id string, newKey Key) (*Handle, error)
}

// MemoryStore 是基于内存的线程安全 Store 实现。
//
// 以互斥锁保护全部操作;Hist/Rotate 的旧版本归档于内部历史切片,可通过 History
// 查询。Store 不自动 Close 条目,删除/轮转后的句柄由调用方负责释放。
//
// MemoryStore is a thread-safe, in-memory implementation of Store.
//
// A mutex guards all operations; superseded handles from Put-overwrites and
// Rotate are archived in an internal history slice queryable through
// History. The store never closes entries automatically — callers release
// handles after deletion or rotation.
type MemoryStore struct {
	mu   sync.RWMutex
	keys map[string]*Handle
	hist map[string][]*Handle
}

// NewMemoryStore 创建空的线程安全内存密钥存储。
//
// NewMemoryStore creates an empty, thread-safe in-memory key store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		keys: make(map[string]*Handle),
		hist: make(map[string][]*Handle),
	}
}

// Get 按 ID 返回密钥条目;不存在时返回 ErrNotFound。
//
// Get returns the entry with the given ID, or ErrNotFound when absent.
func (s *MemoryStore) Get(id string) (*Handle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.keys[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return h, nil
}

// Put 存入(upsert)密钥条目。
// 已存在同 ID 条目时被覆盖,且旧 Handle 进入该 ID 的历史归档(可经 History 查询,
// 调用方负责 Close)。h 为 nil、h.ID 为空时返回错误。
//
// Put stores (upserts) the entry.
// An existing entry with the same ID is overwritten and the previous handle
// is moved into the ID's history archive (queryable via History; the caller
// is responsible for closing it). A nil h or an empty h.ID returns an error.
func (s *MemoryStore) Put(h *Handle) error {
	if h == nil {
		return fmt.Errorf("key: nil handle")
	}
	if h.ID == "" {
		return fmt.Errorf("key: empty handle id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.keys[h.ID]; ok {
		s.hist[h.ID] = append(s.hist[h.ID], prev)
	}
	if h.Algorithm == "" && h.Key != nil {
		h.Algorithm = h.Key.Algorithm()
	}
	s.keys[h.ID] = h
	return nil
}

// Delete 删除指定 ID 的条目;不存在时返回 ErrNotFound。
// 被删除的条目不进入历史归档;其句柄由调用方负责 Close。
//
// Delete removes the entry with the given ID, or returns ErrNotFound when
// absent. Deleted entries are not archived; callers close their handles.
func (s *MemoryStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[id]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	delete(s.keys, id)
	return nil
}

// List 返回全部条目的快照(按 ID 排序)。
//
// List returns a snapshot of all entries, sorted by ID.
func (s *MemoryStore) List() ([]*Handle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Handle, 0, len(s.keys))
	for _, h := range s.keys {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Rotate 用 newKey 轮转指定 ID 的条目。
// 生成 Version = old.Version+1 的新 Handle(保留 Alias 与 Generation,CreatedAt
// 更新为当前时间),并把旧 Handle 追加到该 ID 的历史归档(调用方负责 Close 归档
// 对象,可经 History 获取)。newKey 为 nil 或 ID 不存在时返回错误。
//
// Rotate rotates the entry with the given ID to newKey.
// It produces a new Handle with Version = old.Version+1 (preserving Alias and
// Generation, refreshing CreatedAt) and appends the old handle to the ID's
// history archive (callers close archived handles obtained via History).
// A nil newKey or an absent ID returns an error.
func (s *MemoryStore) Rotate(id string, newKey Key) (*Handle, error) {
	if newKey == nil {
		return nil, fmt.Errorf("key: nil rotation key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.keys[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	next := &Handle{
		ID:         id,
		Alias:      old.Alias,
		Algorithm:  newKey.Algorithm(),
		Version:    old.Version + 1,
		Generation: old.Generation,
		CreatedAt:  time.Now(),
		Key:        newKey,
	}
	s.hist[id] = append(s.hist[id], old)
	s.keys[id] = next
	return next, nil
}

// History 返回指定 ID 的历史归档条目(不含当前条目,旧版本按轮转先后顺序)。
// ID 从未出现过或没有历史时返回空切片;ID 不存在且无任何记录时返回 ErrNotFound。
//
// History returns the archived entries of the given ID (excluding the
// current entry, ordered from oldest to newest rotation).
// It returns an empty slice when the ID has never been archived; when the
// ID is unknown altogether it returns ErrNotFound.
func (s *MemoryStore) History(id string) ([]*Handle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.keys[id]; !ok {
		if _, ok := s.hist[id]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
	}
	out := append([]*Handle(nil), s.hist[id]...)
	return out, nil
}
