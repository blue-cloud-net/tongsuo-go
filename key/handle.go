package key

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Handle 为密钥管理层中的单个密钥条目,携带元数据与密钥本身。
//
// ID 为存储中的唯一标识;Alias 为可选的助记别名;Algorithm 冗余记录算法以方便
// 检索;Version 随每次 Rotate 递增;Generation 由调用方按需维护(跨代归档);
// CreatedAt 记录创建时间;Key 为实际密钥(对称或非对称)。经 Handle.Close 释放
// 底层句柄(对称密钥无句柄,调用为 no-op)。
//
// Handle is a single key entry in the key-management layer, carrying
// metadata together with the key itself.
//
// ID uniquely identifies the entry in a store; Alias is an optional
// mnemonic; Algorithm redundantly records the algorithm for convenient
// lookup; Version increments on every Rotate; Generation is maintained by
// the caller as needed (cross-generation archival); CreatedAt records when
// the entry was created; Key is the actual key (symmetric or asymmetric).
// Release the underlying handle through Handle.Close (a no-op for symmetric
// keys, which own no handle).
type Handle struct {
	ID         string
	Alias      string
	Algorithm  Algorithm
	Version    uint32
	Generation uint64
	CreatedAt  time.Time
	Key        Key
}

// NewHandle 构造一个新的密钥条目。
// id 不能为空、key 不能为 nil;Algorithm 由 key.Algorithm() 自动填充,Version
// 初始为 1,Generation 初始为 0,CreatedAt 取当前时间。已完成闭环释放的语义:
// 调用方使用完毕应调用返回值的 Close 或 key.Close。
//
// NewHandle builds a fresh key entry.
// id must be non-empty and key must be non-nil; Algorithm is filled from
// key.Algorithm(), Version starts at 1, Generation at 0, and CreatedAt is
// the current time. Callers should invoke Close on the returned value (or
// key.Close) once done.
func NewHandle(id string, key Key) (*Handle, error) {
	if id == "" {
		return nil, fmt.Errorf("key: empty handle id")
	}
	if key == nil {
		return nil, fmt.Errorf("key: nil handle key")
	}
	return &Handle{
		ID:         id,
		Algorithm:  key.Algorithm(),
		Version:    1,
		Generation: 0,
		CreatedAt:  time.Now(),
		Key:        key,
	}, nil
}

// Close 释放该条目底层密钥句柄(若有)。
// 委托 key.Close;对称密钥为 no-op,可重复调用。
//
// Close releases the underlying key handle held by the entry, if any.
// It delegates to key.Close; it is a no-op for symmetric keys and may be
// called repeatedly.
func (h *Handle) Close() error {
	if h == nil {
		return nil
	}
	return Close(h.Key)
}

// handleJSON 是 Handle 的 JSON 中间表示,密钥以 PEM 文本内嵌。
//
// handleJSON is the JSON intermediate representation of Handle, embedding
// the key as PEM text.
type handleJSON struct {
	ID         string    `json:"id"`
	Alias      string    `json:"alias,omitempty"`
	Algorithm  Algorithm `json:"algorithm"`
	Version    uint32    `json:"version"`
	Generation uint64    `json:"generation,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	KeyPEM     string    `json:"key_pem"`
}

// MarshalJSON 将 Handle 序列化为 JSON。
// 密钥经各自的 Marshal 转成 PEM 文本内嵌;对称密钥为明文、私钥为未加密 PKCS#8
// ——本序列化面向进程内/受信存储演示,切勿用于磁盘明文持久化私钥。无法导出
// 的密钥类型返回 ErrUnsupported。
//
// MarshalJSON serializes the Handle as JSON.
// The key is embedded as PEM text through its Marshal method; symmetric
// keys are plaintext and private keys are unencrypted PKCS#8 — this
// serialization targets in-process / trusted-store demos and must NOT be
// used to persist private keys as plaintext on disk. Un-exportable key
// types return ErrUnsupported.
func (h *Handle) MarshalJSON() ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("key: nil handle")
	}
	pemBytes, err := marshalKeyPEM(h.Key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(&handleJSON{
		ID:         h.ID,
		Alias:      h.Alias,
		Algorithm:  h.Algorithm,
		Version:    h.Version,
		Generation: h.Generation,
		CreatedAt:  h.CreatedAt,
		KeyPEM:     string(pemBytes),
	})
}

// UnmarshalJSON 从 JSON 还原 Handle。
// 依据内嵌 PEM 块类型还原密钥:SYMMETRIC KEY → ParseSymmetricKey;PUBLIC KEY →
// LoadPublicKeyPEM;其余私钥块 → LoadPrivateKeyPEM(加密私钥块因缺口令会失败)。
//
// UnmarshalJSON restores a Handle from JSON.
// The key is restored according to the embedded PEM block type: SYMMETRIC
// KEY via ParseSymmetricKey, PUBLIC KEY via LoadPublicKeyPEM, and other
// private-key blocks via LoadPrivateKeyPEM (encrypted private-key blocks
// fail because no passphrase is available).
func (h *Handle) UnmarshalJSON(data []byte) error {
	var j handleJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	k, err := parseKeyPEM([]byte(j.KeyPEM))
	if err != nil {
		return err
	}
	h.ID = j.ID
	h.Alias = j.Alias
	h.Algorithm = j.Algorithm
	h.Version = j.Version
	h.Generation = j.Generation
	h.CreatedAt = j.CreatedAt
	h.Key = k
	return nil
}

// marshalKeyPEM 将任意支持的密钥转为 PEM 文本。
//
// marshalKeyPEM converts any supported key to PEM text.
func marshalKeyPEM(k Key) ([]byte, error) {
	switch key := k.(type) {
	case SymmetricKey:
		return key.Marshal()
	case AsymmetricPrivateKey:
		return key.Marshal()
	case AsymmetricPublicKey:
		return key.Marshal()
	default:
		return nil, ErrUnsupported
	}
}

// parseKeyPEM 依据 PEM 块类型将文本还原为密钥。
//
// parseKeyPEM restores a key from PEM text based on the block type.
func parseKeyPEM(p []byte) (Key, error) {
	block, err := ParsePEM(p)
	if err != nil {
		return nil, err
	}
	switch {
	case block.Type == symmetricPEMType:
		return ParseSymmetricKey(p)
	case strings.HasSuffix(block.Type, "PUBLIC KEY"):
		return LoadPublicKeyPEM(p)
	default:
		return LoadPrivateKeyPEM(p)
	}
}
