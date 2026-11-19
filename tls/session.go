package tls

import (
	"bytes"
	"container/list"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// ErrNoSession 表示尚未收到可恢复会话。
//
// ErrNoSession indicates that no resumable session has been received.
var ErrNoSession = errors.New("tls: no resumable session")

// SessionState 保存不可变会话；序列化结果包含秘密，调用方负责保护及清零输出切片。
//
// SessionState holds an immutable session; serialized output contains secrets that callers must protect and clear.
type SessionState struct {
	der       []byte
	info      core.SessionInfo
	binding   string
	peers     [][]byte
	ocsp      []byte
	ocspChain [][]byte
}

// ParseSessionDER 解析最大 1 MiB 的完整原生会话 DER；不授予信任，过期会话不能恢复。
//
// ParseSessionDER parses complete native session DER up to 1 MiB without granting trust; expired sessions cannot resume.
func ParseSessionDER(data []byte) (*SessionState, error) {
	info, der, err := core.DecodeSession(data)
	if err != nil {
		return nil, fmt.Errorf("tls: parse session: %w", err)
	}
	return &SessionState{der: der, info: info}, nil
}

// ParseSessionPEM 解析单个 SSL SESSION PARAMETERS 块，拒绝额外数据及超过 2 MiB 的输入。
//
// ParseSessionPEM parses one SSL SESSION PARAMETERS block, rejecting trailing data and inputs over 2 MiB.
func ParseSessionPEM(data []byte) (*SessionState, error) {
	if len(data) > 2<<20 {
		return nil, errors.New("tls: session PEM too large")
	}
	data = bytes.TrimSpace(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN SSL SESSION PARAMETERS-----")) {
		return nil, errors.New("tls: invalid session PEM")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "SSL SESSION PARAMETERS" || len(block.Headers) > 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("tls: invalid session PEM")
	}
	return ParseSessionDER(block.Bytes)
}

// MarshalDER 返回含秘密的独立 DER；nil 会话返回错误，调用方负责清零输出切片。
//
// MarshalDER returns independent secret DER, or an error for nil sessions; callers must clear the output.
func (s *SessionState) MarshalDER() ([]byte, error) {
	if s == nil || len(s.der) == 0 {
		return nil, ErrNoSession
	}
	return append([]byte(nil), s.der...), nil
}

// MarshalPEM 返回含秘密的原生 PEM；调用方负责清零输出切片。
//
// MarshalPEM returns native PEM containing secrets; callers must clear the output.
func (s *SessionState) MarshalPEM() ([]byte, error) {
	der, err := s.MarshalDER()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "SSL SESSION PARAMETERS", Bytes: der}), nil
}

// SessionMetadata 提供不含会话密钥的只读快照。
//
// SessionMetadata provides a read-only snapshot without session keys.
type SessionMetadata struct {
	// Version 为协议版本。
	//
	// Version is the protocol version.
	Version uint16
	// CreatedAt 为创建时间。
	//
	// CreatedAt is the creation time.
	CreatedAt time.Time
	// ExpiresAt 为到期时间。
	//
	// ExpiresAt is the expiration time.
	ExpiresAt time.Time
	// HasTicket 标记包含票据。
	//
	// HasTicket reports whether a ticket is present.
	HasTicket bool
	// Resumable 表示尚未过期且原生允许恢复，不保证下一次握手被接受。
	//
	// Resumable reports native eligibility before expiry, without guaranteeing acceptance.
	Resumable bool
	// ID 为独立会话标识副本。
	//
	// ID is an independent session identifier.
	ID []byte
}

// Metadata 返回不含秘密的独立元数据；nil 返回零值。
//
// Metadata returns independent non-secret metadata, or zero for nil receivers.
func (s *SessionState) Metadata() SessionMetadata {
	if s == nil {
		return SessionMetadata{}
	}
	return SessionMetadata{s.info.Version, s.info.Created, s.info.Expires, s.info.HasTicket, s.usable(), append([]byte(nil), s.info.ID...)}
}
func (s *SessionState) usable() bool {
	return s != nil && s.info.Resumable && time.Now().Before(s.info.Expires)
}
func copySession(s *SessionState) *SessionState {
	if s == nil {
		return nil
	}
	out := *s
	out.der = append([]byte(nil), s.der...)
	out.info.ID = append([]byte(nil), s.info.ID...)
	out.peers = cloneDER(s.peers)
	out.ocsp = append([]byte(nil), s.ocsp...)
	out.ocspChain = cloneDER(s.ocspChain)
	return &out
}

// SessionCache 是并发安全的会话存储；Put 的 nil 值删除条目，回调不得重入连接。
//
// SessionCache is concurrent session storage; Put with nil deletes entries and callbacks must not reenter connections.
type SessionCache interface {
	// Get 返回缓存条目；实现不得修改会话对象。
	//
	// Get returns a cached entry without modifying session objects.
	Get(string) (*SessionState, bool)
	// Put 保存或删除缓存条目；键由 SDK 构造，包含隔离域。
	//
	// Put stores or removes an entry under an SDK key containing its isolation domain.
	Put(string, *SessionState)
}

// ServerSessionCache 是服务端有状态会话存储接口；不包含票据密钥。
//
// ServerSessionCache is server-side stateful session storage without ticket keys.
type ServerSessionCache interface{ SessionCache }

type memorySessionCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[string]*list.Element
	lru      *list.List
}
type sessionEntry struct {
	key   string
	value *SessionState
}

// NewSessionCache 创建并发安全的 LRU 缓存；容量小于一时返回错误。
//
// NewSessionCache creates a concurrent LRU cache, returning an error for capacity below one.
func NewSessionCache(capacity int) (SessionCache, error) {
	if capacity < 1 {
		return nil, errors.New("tls: session cache capacity must be positive")
	}
	return &memorySessionCache{capacity: capacity, entries: make(map[string]*list.Element), lru: list.New()}, nil
}
func (m *memorySessionCache) Get(key string) (*SessionState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el := m.entries[key]
	if el == nil {
		return nil, false
	}
	s := el.Value.(sessionEntry).value
	if !s.usable() {
		m.lru.Remove(el)
		delete(m.entries, key)
		return nil, false
	}
	m.lru.MoveToFront(el)
	return copySession(s), true
}
func (m *memorySessionCache) Put(key string, s *SessionState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if el := m.entries[key]; el != nil {
		m.lru.Remove(el)
		delete(m.entries, key)
	}
	if s == nil || !s.usable() {
		return
	}
	el := m.lru.PushFront(sessionEntry{key, copySession(s)})
	m.entries[key] = el
	if m.lru.Len() > m.capacity {
		old := m.lru.Back()
		delete(m.entries, old.Value.(sessionEntry).key)
		m.lru.Remove(old)
	}
}

// TicketKey 是 64 字节票据密钥：16 字节名称、16 字节 AES 密钥和 32 字节 HMAC 密钥。
//
// TicketKey is a 64-byte ticket key: 16-byte name, 16-byte AES key and 32-byte HMAC key.
type TicketKey [64]byte

// GenerateTicketKey 使用系统安全随机源生成密钥；调用方负责清零返回值。
//
// GenerateTicketKey uses the system secure random source; callers must clear the returned key.
func GenerateTicketKey() (TicketKey, error) {
	var k TicketKey
	_, err := io.ReadFull(rand.Reader, k[:])
	return k, err
}

// TicketKeyManager 并发管理密钥环；默认每日按需轮换并保留七天，显式密钥环由调用方轮换。
//
// TicketKeyManager manages a concurrent ring; defaults rotate daily on use and retain seven days, while explicit rings require caller rotation.
type TicketKeyManager struct {
	mu        sync.Mutex
	keys      []TicketKey
	created   time.Time
	automatic bool
	ages      []time.Time
}

// NewTicketKeyManager 创建自动轮换密钥管理器；随机源失败返回错误。
//
// NewTicketKeyManager creates an automatically rotating manager, returning random source errors.
func NewTicketKeyManager() (*TicketKeyManager, error) {
	k, err := GenerateTicketKey()
	if err != nil {
		return nil, err
	}
	return &TicketKeyManager{keys: []TicketKey{k}, created: time.Now(), automatic: true, ages: []time.Time{time.Now()}}, nil
}

// SetKeys 原子替换显式密钥环并关闭自动轮换；首项签发，其余解密，拒绝空环或重复名称。
//
// SetKeys atomically replaces the explicit ring and disables automatic rotation; the first issues and others decrypt, rejecting empty rings or duplicate names.
func (m *TicketKeyManager) SetKeys(keys []TicketKey) error {
	if m == nil || len(keys) == 0 || len(keys) > 32 {
		return errors.New("tls: invalid ticket key ring")
	}
	names := map[[16]byte]bool{}
	for _, k := range keys {
		var name [16]byte
		copy(name[:], k[:16])
		if names[name] {
			return errors.New("tls: duplicate ticket key name")
		}
		names[name] = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys = append([]TicketKey(nil), keys...)
	m.automatic = false
	return nil
}
func (m *TicketKeyManager) selectKey(name []byte, encrypt bool) ([]byte, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.automatic && time.Since(m.created) >= 24*time.Hour {
		k, err := GenerateTicketKey()
		if err != nil {
			return nil, -1
		}
		if time.Since(m.created) >= 7*24*time.Hour {
			m.keys = nil
			m.ages = nil
		}
		m.keys = append([]TicketKey{k}, m.keys...)
		m.ages = append([]time.Time{time.Now()}, m.ages...)
		if len(m.keys) > 7 {
			m.keys = m.keys[:7]
			m.ages = m.ages[:7]
		}
		m.created = time.Now()
	}
	if m.automatic {
		for len(m.ages) > 0 && time.Since(m.ages[len(m.ages)-1]) >= 7*24*time.Hour {
			m.ages = m.ages[:len(m.ages)-1]
			m.keys = m.keys[:len(m.keys)-1]
		}
	}
	if len(m.keys) == 0 {
		return nil, -1
	}
	if encrypt {
		return append([]byte(nil), m.keys[0][:]...), 1
	}
	for i, k := range m.keys {
		if bytes.Equal(name, k[:16]) {
			status := 1
			if i > 0 {
				status = 2
			}
			return append([]byte(nil), k[:]...), status
		}
	}
	return nil, 0
}

// SessionState 返回最新可恢复会话的独立快照；握手未完成、已关闭或票据未到时返回错误。
//
// SessionState returns an independent resumable session snapshot, failing before handshake completion, after Close or before ticket receipt.
func (c *Conn) SessionState() (*SessionState, error) {
	if c == nil || !c.handshakeDone.Load() || c.closed.Load() {
		return nil, ErrNoSession
	}
	data := c.ssl.SessionDER()
	if len(data) == 0 {
		if c.resuming != nil && c.ConnectionState().SessionReused && c.resuming.usable() {
			return copySession(c.resuming), nil
		}
		return nil, ErrNoSession
	}
	s, err := ParseSessionDER(data)
	if err != nil {
		return nil, err
	}
	if !s.usable() {
		return nil, ErrNoSession
	}
	s.binding = c.sessionKey
	state := c.ConnectionState()
	s.peers = state.PeerCertificates
	if state.OCSPVerification == VerificationPassed && len(state.VerifiedChains) > 0 {
		s.ocsp = state.OCSPResponse
		s.ocspChain = state.VerifiedChains[0]
	}
	if c.config != nil && c.config.SessionCache != nil && c.sessionKey != "" {
		c.config.SessionCache.Put(c.sessionKey, copySession(s))
	}
	return s, nil
}

// WaitSession 等待可恢复会话，不改变期限；应用数据最多暂存 64 KiB，超限报错并保留已读取数据。
//
// WaitSession waits for a resumable session without changing deadlines; it buffers up to 64 KiB of application data and reports overflow while retaining consumed bytes.
func (c *Conn) WaitSession(ctx context.Context) (*SessionState, error) {
	if ctx == nil {
		return nil, errors.New("tls: nil session context")
	}
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	// Waiting for an active reader is cancellable as well.
	for !c.mu.TryLock() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
	defer c.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if s, err := c.SessionState(); err == nil {
			return s, nil
		} else if !errors.Is(err, ErrNoSession) {
			return nil, err
		}
		const pendingLimit = 64 * 1024
		available := pendingLimit - len(c.sessionPending)
		if available <= 0 {
			return nil, errors.New("tls: session wait application buffer limit")
		}
		data, err := c.ssl.PumpSession(ctx, available)
		c.sessionPending = append(c.sessionPending, data...)
		if err != nil {
			return nil, err
		}
	}
}

// Configuration identity is initialized without copying locks or retaining configurations globally.
var sessionConfigMu sync.Mutex

type sessionScope struct {
	mu sync.Mutex
	id string
}

func (scope *sessionScope) identifier() (string, error) {
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if scope.id == "" {
		var token [32]byte
		if _, err := io.ReadFull(rand.Reader, token[:]); err != nil {
			return "", fmt.Errorf("tls: session isolation entropy: %w", err)
		}
		scope.id = hex.EncodeToString(token[:])
	}
	return scope.id, nil
}
func (cfg *Config) cloneRuntime() *Config {
	if cfg == nil {
		return &Config{sessionScope: &sessionScope{}}
	}
	sessionConfigMu.Lock()
	if cfg.sessionScope == nil {
		cfg.sessionScope = &sessionScope{}
	}
	scope := cfg.sessionScope
	sessionConfigMu.Unlock()
	out := cfg.Clone()
	out.sessionScope = scope
	return out
}

func sessionDomain(cfg *Config, endpoint string) (string, error) {
	scope := cfg.SessionPolicyID
	if scope == "" {
		if cfg.sessionScope == nil {
			return "", errors.New("tls: session isolation scope missing")
		}
		var err error
		scope, err = cfg.sessionScope.identifier()
		if err != nil {
			return "", err
		}
	}
	groups := [][]*x509.Certificate{{cfg.Cert, cfg.SignCert, cfg.EncCert}, cfg.CertChain, cfg.SignChain, cfg.EncChain, cfg.RootCAs, cfg.ClientCAs}
	certificates := make([][][]byte, len(groups))
	for i, group := range groups {
		certificates[i] = make([][]byte, len(group))
		for j, cert := range group {
			if cert == nil {
				continue
			}
			der, err := cert.MarshalDER()
			if err != nil {
				return "", err
			}
			certificates[i][j] = der
		}
	}
	// JSON preserves string/list boundaries; textual concatenation would permit ambiguous keys.
	identity := struct {
		Scope        string
		Endpoint     string
		Parameters   []any
		Certificates [][][]byte
	}{
		scope, endpoint, []any{cfg.Protocol, cfg.NTLS, cfg.RFC8998, cfg.MinVersion, cfg.MaxVersion, cfg.ServerName, cfg.VerificationName, cfg.DisableSNI, cfg.Verification, cfg.InsecureSkipVerify, cfg.ClientAuth, cfg.HostnameOptions, cfg.CipherSuites, cfg.NextProtos, cfg.CurvePreferences, cfg.SignatureAlgorithms, cfg.Options, cfg.Modes, cfg.StrictConfig, cfg.DHParameters, cfg.OCSPPolicy, cfg.RequestOCSP}, certificates,
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("tls: session identity: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func configureSessions(ctx *core.TLSContext, cfg *Config, client bool) error {
	domain, err := sessionDomain(cfg, "")
	if err != nil {
		return err
	}
	raw, _ := hex.DecodeString(domain)
	tickets := -1
	if cfg.SessionTicketCount != nil {
		tickets = *cfg.SessionTicketCount
		if tickets < 0 || tickets > 16 {
			return errors.New("tls: ticket count outside 0..16")
		}
	}
	var get func([]byte) []byte
	var put func([]byte, []byte)
	var key func([]byte, bool) ([]byte, int)
	if !client {
		if cfg.TicketKeys == nil {
			cfg.TicketKeys, err = NewTicketKeyManager()
			if err != nil {
				return err
			}
		}
		if cfg.ServerSessionCache == nil {
			cfg.ServerSessionCache, err = NewSessionCache(256)
			if err != nil {
				return err
			}
		}
		get = func(id []byte) []byte {
			s, ok := cfg.ServerSessionCache.Get(domain + ":" + hex.EncodeToString(id))
			if !ok || !s.usable() {
				return nil
			}
			return append([]byte(nil), s.der...)
		}
		put = func(id, data []byte) {
			s, e := ParseSessionDER(data)
			if e == nil {
				cfg.ServerSessionCache.Put(domain+":"+hex.EncodeToString(id), s)
			}
		}
		key = cfg.TicketKeys.selectKey
	}
	return ctx.ConfigureSessions(!client, cfg.SessionTicketsDisabled, tickets, raw, get, put, key)
}
func (c *Conn) installSession(addr string) error {
	cfg := c.config
	key, err := sessionDomain(cfg, addr)
	if err != nil {
		return err
	}
	c.sessionKey = key
	s := cfg.Session
	if s == nil && cfg.SessionCache != nil {
		s, _ = cfg.SessionCache.Get(key)
	}
	if s == nil || !s.usable() {
		return nil
	}
	if s.info.Version == NTLSVersion && len(s.peers) < 2 {
		return nil
	}
	if s.binding != "" && s.binding != key {
		return nil
	}

	if cfg.OCSPPolicy != OCSPUnchecked {
		if len(s.ocsp) == 0 || verifySessionStaple(cfg, s) != nil {
			return nil
		}
	}
	if err := c.ssl.SetSession(s.der); err != nil {
		return err
	}
	c.resuming = copySession(s)
	return nil
}

// WithPeerCertificates 附加独立证书链供恢复后重新验证；不授予信任，叶证书必须与会话一致。
//
// WithPeerCertificates attaches a copied chain for revalidation without granting trust; its leaf must match the session.
func (s *SessionState) WithPeerCertificates(peers [][]byte) (*SessionState, error) {
	if s == nil || len(peers) == 0 || len(peers) > 100 {
		return nil, errors.New("tls: invalid session peer chain")
	}
	total := 0
	for _, der := range peers {
		total += len(der)
		if total > 1<<20 {
			return nil, errors.New("tls: session peer chain too large")
		}
		cert, err := x509.LoadCertificateDER(der)
		if err != nil {
			return nil, err
		}
		if err := cert.Close(); err != nil {
			return nil, err
		}
	}
	out := copySession(s)
	if !bytes.Equal(s.info.Peer, peers[0]) {
		return nil, errors.New("tls: session peer leaf mismatch")
	}
	out.peers = cloneDER(peers)
	return out, nil
}

func (c *Conn) cacheSession() error {
	if c.config == nil || c.config.SessionCache == nil {
		return nil
	}
	_, err := c.SessionState()
	if errors.Is(err, ErrNoSession) {
		return nil
	}
	return err
}
