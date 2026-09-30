package keystore

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/keyaccess"
)

// KeyDecoder 把 PEM 文本还原为具体密钥对象。
//
// 本包不 import asym / sym（避免反向依赖），因此「PEM → 密钥」这一步由调用方
// 注入。典型实现按 PEM 块类型分派到 asym.LoadPrivateKeyPEM /
// asym.LoadPublicKeyPEM / sym.ParseSymmetricKey。
//
// KeyDecoder turns PEM text back into a concrete key object.
//
// Because this package does not import asym or sym (avoiding reverse
// dependencies), the "PEM to key" step is injected by the caller. A typical
// implementation dispatches on the PEM block type to asym.LoadPrivateKeyPEM,
// asym.LoadPublicKeyPEM or sym.ParseSymmetricKey.
type KeyDecoder func(pemBytes []byte) (any, error)

// algNamer 是能从密钥对象读出算法名的窄接口，返回类型必须是 string。
//
// 目前无类型满足该形状（asym.Algorithm / sym.Algorithm 都是具名字符串类型），
// 保留它是为了让将来 algo 方法改回 string 返回值时能直接命中，无须反射。
//
// algNamer is the narrow interface that exposes a key's algorithm name, with
// a string return type.
//
// No type satisfies it today (asym.Algorithm and sym.Algorithm are both
// named string types); it is kept so that a future switch back to a string
// return type is picked up directly, without reflection.
type algNamer interface {
	Algorithm() string
}

// pemMarshaller 是能自行导出为 PEM 的对称密钥形状（sym.SymmetricKey）。
//
// pemMarshaller is the symmetric-key shape that exports itself as PEM
// (sym.SymmetricKey).
type pemMarshaller interface {
	Marshal() ([]byte, error)
}

// privatePEMWriter 是非对称私钥的 PEM 导出形状（asym.PrivateKey）。
//
// privatePEMWriter is the PEM-export shape of an asymmetric private key
// (asym.PrivateKey).
type privatePEMWriter interface {
	MarshalPrivateKeyPEM() ([]byte, error)
}

// publicPEMWriter 是非对称公钥的 PEM 导出形状（asym.PublicKey）。
//
// publicPEMWriter is the PEM-export shape of an asymmetric public key
// (asym.PublicKey).
type publicPEMWriter interface {
	MarshalPublicKeyPEM() ([]byte, error)
}

// Handle 是密钥管理层中的单个密钥条目，携带元数据与密钥本身。
//
// ID 为存储中的唯一标识；Alias 为可选的助记别名；Algorithm 冗余记录算法名以便
// 检索（由 NewHandle 自动填充）；Version 随每次 Rotate 递增；Generation 由调用
// 方按需维护（跨代归档）；CreatedAt 记录创建时间；Key 为实际密钥对象（对称或非
// 对称，类型为 any 以避免本包反向依赖 asym / sym）。
//
// 经 Handle.Close 释放底层句柄（对称密钥无句柄，调用为 no-op）。
//
// Handle is a single key entry in the key-management layer, carrying
// metadata together with the key itself.
//
// ID uniquely identifies the entry in a store; Alias is an optional mnemonic;
// Algorithm redundantly records the algorithm name for convenient lookup
// (filled automatically by NewHandle); Version increments on every Rotate;
// Generation is maintained by the caller as needed (cross-generation
// archival); CreatedAt records when the entry was created; Key is the actual
// key object (symmetric or asymmetric, typed any so this package does not
// depend on asym or sym).
//
// Release the underlying handle through Handle.Close (a no-op for symmetric
// keys, which own no handle).
type Handle struct {
	ID         string
	Alias      string
	Algorithm  string
	Version    uint32
	Generation uint64
	CreatedAt  time.Time
	Key        any

	// decoder 是反序列化时使用的 PEM 解码器，不参与序列化。
	// 经 SetDecoder 注入；json.Unmarshal 直接调用 UnmarshalJSON 时若缺失
	// 则返回 ErrNoDecoder。
	//
	// decoder is the PEM decoder used during unmarshalling; it is never
	// serialised. Inject it with SetDecoder; UnmarshalJSON returns
	// ErrNoDecoder when it is absent.
	decoder KeyDecoder
}

// NewHandle 构造一个新的密钥条目。
//
// id 不能为空、key 不能为 nil；Algorithm 由 key 的 Algorithm() 自动填充（方法
// 返回值经 String() 语义转成 string），Version 初始为 1，Generation 初始为 0，
// CreatedAt 取当前时间。调用方使用完毕应调用返回值的 Close。
//
// NewHandle builds a fresh key entry.
//
// id must be non-empty and key must be non-nil; Algorithm is filled from the
// key's Algorithm() method (stringified), Version starts at 1, Generation at
// 0, and CreatedAt is the current time. Callers should invoke Close on the
// returned value once done.
func NewHandle(id string, key any) (*Handle, error) {
	if id == "" {
		return nil, fmt.Errorf("keystore: empty handle id")
	}
	if key == nil {
		return nil, fmt.Errorf("keystore: nil handle key")
	}
	return &Handle{
		ID:         id,
		Algorithm:  algorithmName(key),
		Version:    1,
		Generation: 0,
		CreatedAt:  time.Now(),
		Key:        key,
	}, nil
}

// SetDecoder 注入 PEM 解码器并返回接收者本身（便于链式调用）。
//
// 仅在需要经 encoding/json 反序列化（json.Unmarshal 调用 UnmarshalJSON）时
// 必要；使用 UnmarshalHandle 可省略本步骤。
//
// SetDecoder injects the PEM decoder and returns the receiver for chaining.
//
// It is only needed when unmarshalling through encoding/json (json.Unmarshal
// calling UnmarshalJSON); UnmarshalHandle makes it unnecessary.
func (h *Handle) SetDecoder(d KeyDecoder) *Handle {
	if h == nil {
		return nil
	}
	h.decoder = d
	return h
}

// Close 释放该条目底层密钥句柄（若有），幂等。
//
// 对称密钥不持有原生句柄，调用为 no-op。h 为 nil 时返回 nil。
//
// Close releases the underlying key handle held by the entry, if any; it is
// idempotent.
//
// Symmetric keys own no native handle, so the call is a no-op. A nil h
// returns nil.
func (h *Handle) Close() error {
	if h == nil {
		return nil
	}
	return Close(h)
}

// Close 释放条目底层密钥持有的原生句柄（若有），幂等。
//
// h 或 h.Key 为 nil 时返回 nil。非对称密钥经 internal/keyaccess 取到底层
// EVP_PKEY 句柄后调用其幂等的 Close；对称密钥与非本库密钥类型直接返回 nil。
//
// 注意：不复制句柄。此处释放的正是密钥对象自己持有的那个句柄，与
// keyaccess 文档中「取到后须 Dup」的约定不同——那条约定针对的是「取出来继续
// 使用」，而这里是「归还所有权」。
//
// Close releases the native handle held by the entry's key, if any; it is
// idempotent.
//
// A nil h or h.Key returns nil. For asymmetric keys it obtains the
// underlying EVP_PKEY handle through internal/keyaccess and invokes its
// idempotent Close; symmetric keys and non-library key types return nil
// immediately.
//
// Note that the handle is deliberately not duplicated: what is released here
// is the very handle owned by the key object, unlike the "Dup after
// extracting" rule in the keyaccess documentation — that rule covers
// extracting a handle for further use, whereas this is returning ownership.
func Close(h *Handle) error {
	if h == nil || h.Key == nil {
		return nil
	}
	p, ok := keyaccess.PKey(h.Key)
	if !ok || p == nil {
		return nil
	}
	return p.Close()
}

// handleJSON 是 Handle 的 JSON 中间表示，密钥以 PEM 文本内嵌。
//
// handleJSON is the JSON intermediate representation of Handle, embedding
// the key as PEM text.
type handleJSON struct {
	ID         string    `json:"id"`
	Alias      string    `json:"alias,omitempty"`
	Algorithm  string    `json:"algorithm"`
	Version    uint32    `json:"version"`
	Generation uint64    `json:"generation,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	KeyPEM     string    `json:"key_pem"`
}

// MarshalJSON 将 Handle 序列化为 JSON。
//
// 密钥经各自的方法转成 PEM 文本内嵌：对称密钥用 Marshal（明文），非对称私钥用
// MarshalPrivateKeyPEM（未加密 PKCS#8），公钥用 MarshalPublicKeyPEM。
//
// ⚠️ 安全提示：对称密钥明文、私钥未加密，本序列化只适用于受信存储或进程内分发，
// 不得用于不可信信道，也不应把私钥以明文落盘。
//
// 不支持的密钥类型返回 ErrUnsupported；h 为 nil 时返回错误。
//
// MarshalJSON serializes the Handle as JSON.
//
// The key is embedded as PEM text through its own method: symmetric keys via
// Marshal (plaintext), asymmetric private keys via MarshalPrivateKeyPEM
// (unencrypted PKCS#8) and public keys via MarshalPublicKeyPEM.
//
// ⚠️ Security note: symmetric keys are plaintext and private keys are
// unencrypted, so this serialization only suits trusted stores or in-process
// hand-off; it must not be used over untrusted channels, and private keys
// must not be persisted to disk in cleartext.
//
// Unsupported key types return ErrUnsupported; a nil h returns an error.
func (h *Handle) MarshalJSON() ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("keystore: nil handle")
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
//
// 元数据（ID / Alias / Algorithm / Version / Generation / CreatedAt）总是还原；
// 密钥需经 PEM 解码器还原，因此必须先用 SetDecoder 注入（或改用
// UnmarshalHandle），否则返回 ErrNoDecoder 并且不修改接收者。
//
// UnmarshalJSON restores a Handle from JSON.
//
// Metadata (ID, Alias, Algorithm, Version, Generation, CreatedAt) is always
// restored; the key requires a PEM decoder, so inject one with SetDecoder
// first (or use UnmarshalHandle). Without a decoder it returns ErrNoDecoder
// and leaves the receiver unmodified.
func (h *Handle) UnmarshalJSON(data []byte) error {
	var j handleJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	if h.decoder == nil {
		return fmt.Errorf("%w: %s", ErrNoDecoder, h.ID)
	}
	key, err := h.decoder([]byte(j.KeyPEM))
	if err != nil {
		return fmt.Errorf("keystore: decode key of %q: %w", j.ID, err)
	}
	h.ID = j.ID
	h.Alias = j.Alias
	h.Algorithm = j.Algorithm
	h.Version = j.Version
	h.Generation = j.Generation
	h.CreatedAt = j.CreatedAt
	h.Key = key
	return nil
}

// UnmarshalHandle 从 JSON 还原 Handle，密钥解析委托给 decode。
//
// 这是推荐的反序列化入口：无须先构造 Handle 再注入解码器。
//
// UnmarshalHandle restores a Handle from JSON, delegating key parsing to
// decode.
//
// This is the recommended entry point: there is no need to build a Handle
// and inject the decoder first.
func UnmarshalHandle(data []byte, decode KeyDecoder) (*Handle, error) {
	if decode == nil {
		return nil, fmt.Errorf("%w: nil decoder", ErrNoDecoder)
	}
	h := &Handle{decoder: decode}
	if err := json.Unmarshal(data, h); err != nil {
		return nil, err
	}
	return h, nil
}

// marshalKeyPEM 将任意支持的密钥转为 PEM 文本。
//
// 依次尝试对称密钥的 Marshal、非对称私钥的 MarshalPrivateKeyPEM、公钥的
// MarshalPublicKeyPEM；都不满足时返回 ErrUnsupported。
//
// marshalKeyPEM converts any supported key to PEM text.
//
// It tries, in order, the symmetric Marshal, the asymmetric private
// MarshalPrivateKeyPEM and the public MarshalPublicKeyPEM; when none
// applies it returns ErrUnsupported.
func marshalKeyPEM(key any) ([]byte, error) {
	switch k := key.(type) {
	case pemMarshaller:
		return k.Marshal()
	case privatePEMWriter:
		return k.MarshalPrivateKeyPEM()
	case publicPEMWriter:
		return k.MarshalPublicKeyPEM()
	}
	return nil, fmt.Errorf("%w: %T", ErrUnsupported, key)
}

// algorithmName 从任意密钥对象提取算法名。
//
// 优先命中 algNamer（Algorithm() string）；否则用反射调用 Algorithm() 并把具名
// 字符串类型（asym.Algorithm / sym.Algorithm 都是 type Algorithm string）转成
// string。之所以需要反射：Go 的接口满足要求方法签名完全一致，返回具名类型的
// Algorithm() 无法满足返回 string 的结构化接口；而本包又不能 import asym / sym
// （见 docs/refactor-roadmap.md §3.9）。对象不提供 Algorithm() 时返回空串，由
// 调用方自行填写 Handle.Algorithm。
//
// algorithmName extracts the algorithm name from any key object.
//
// It first tries the algNamer shape (Algorithm() string); otherwise it uses
// reflection to call Algorithm() and stringify the named string type
// (asym.Algorithm and sym.Algorithm are both `type Algorithm string`).
// Reflection is required because Go interface satisfaction demands an
// exactly matching signature: an Algorithm() returning a named type cannot
// satisfy a structural interface returning string, and this package must not
// import asym or sym (see docs/refactor-roadmap.md §3.9). Objects without an
// Algorithm() method yield an empty string, leaving Handle.Algorithm for the
// caller to fill in.
func algorithmName(key any) string {
	if key == nil {
		return ""
	}
	if a, ok := key.(algNamer); ok {
		return a.Algorithm()
	}
	m := reflect.ValueOf(key).MethodByName("Algorithm")
	if !m.IsValid() {
		return ""
	}
	t := m.Type()
	if t.NumIn() != 0 || t.NumOut() != 1 || t.Out(0).Kind() != reflect.String {
		return ""
	}
	return m.Call(nil)[0].String()
}
