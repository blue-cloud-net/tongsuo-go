package mac

import (
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// ErrUnknownAlgorithm 表示按算法名分发时传入的名称不在 Names() 内。
// 按名入口返回的错误均可用 errors.Is(err, ErrUnknownAlgorithm) 判定。
//
// ErrUnknownAlgorithm reports that a by-name entry was given a name not
// present in Names(). Errors from the by-name entries can be tested with
// errors.Is(err, ErrUnknownAlgorithm).
var ErrUnknownAlgorithm = errors.New("mac: unknown algorithm")

// Options 覆盖 MAC 算法的可选参数。
// 全部字段均为「不指定即用默认值」——置零值即可。
//
// 字段语义映射铜锁 CLI 的 -macopt：
//
//	Cipher   → -macopt cipher:<name>      （CMAC / GMAC 时使用）
//	IV       → -macopt hexiv:<hex>        （GMAC 时使用）
//	AAD      → -macopt aad:<hex>          （GMAC 时使用）
//	Custom   → -macopt custom:<hex>       （KMAC 时使用）
//	OutputLen → -macopt size:<bytes>      （KMAC / SipHash 等可截断输出）
//
// 本版走 legacy HMAC_CTX_* 路径，本类型未生效；保留字段以便 0.4.0 接 EVP_MAC_*
// 时直接复用。
//
// Options holds optional MAC algorithm parameters. Zero values mean
// "use the default". Field semantics map to Tongsuo CLI -macopt keys;
// see the per-field comments.
//
// This version uses the legacy HMAC_CTX_* path and ignores Options;
// the type is reserved so the 0.4.0 EVP_MAC_* migration can reuse it
// without breaking callers.
type Options struct {
	// Cipher 指定 CMAC / GMAC 用的对称算法名（如 "SM4"、"AES-128-CBC"）。
	//
	// Cipher selects the symmetric algorithm used by CMAC / GMAC.
	Cipher string
	// IV 是 GMAC 的初始向量（nil/空表示让铜锁生成默认 IV）。
	//
	// IV is the initial vector for GMAC (nil/empty lets Tongsuo pick one).
	IV []byte
	// AAD 是 GMAC 的附加认证数据（authenticated but not encrypted）。
	//
	// AAD holds Additional Authenticated Data for GMAC.
	AAD []byte
	// Custom 是 KMAC 的 customization 串。
	//
	// Custom is the KMAC customization string.
	Custom []byte
	// OutputLen 指定输出字节数（0 表示按算法默认；KMAC 必须显式指定）。
	//
	// OutputLen is the requested output size in bytes (0 = default).
	OutputLen int
}

// algo 描述一个已支持的 MAC 算法：名称、标签长度与底层摘要工厂。
//
// algo describes one supported MAC algorithm: name, tag size and the
// core-layer descriptor factory.
type algo struct {
	name string
	tag  int
	desc func() *core.Digest
}

// algos 是算法注册表；切片顺序即 Names() 的返回顺序（稳定）。
//
// algos is the algorithm registry; the slice order defines the stable
// order returned by Names().
var algos = []algo{
	{"HMAC-SM3", 32, core.SM3},
	{"HMAC-MD5", 16, core.MD5},
	{"HMAC-SHA1", 20, core.SHA1},
	{"HMAC-SHA224", 28, core.SHA224},
	{"HMAC-SHA256", 32, core.SHA256},
	{"HMAC-SHA384", 48, core.SHA384},
	{"HMAC-SHA512", 64, core.SHA512},
}

// lookup 按算法名查找注册项；名称大小写不敏感。
//
// lookup resolves an algorithm by name; matching is case-insensitive.
func lookup(name string) (algo, error) {
	key := strings.ToUpper(strings.TrimSpace(name))
	for _, a := range algos {
		if a.name == key {
			return a, nil
		}
	}
	return algo{}, fmt.Errorf("mac: %q: %w", name, ErrUnknownAlgorithm)
}

// Names 返回本版支持的 MAC 算法名，顺序稳定
// （HMAC-SM3 / HMAC-MD5 / HMAC-SHA1 / HMAC-SHA224 / HMAC-SHA256 /
// HMAC-SHA384 / HMAC-SHA512）。
//
// Names returns the MAC algorithm names supported by this version in a
// stable order (HMAC-SM3 / HMAC-MD5 / HMAC-SHA1 / HMAC-SHA224 /
// HMAC-SHA256 / HMAC-SHA384 / HMAC-SHA512).
func Names() []string {
	out := make([]string, len(algos))
	for i, a := range algos {
		out[i] = a.name
	}
	return out
}

// New 按算法名返回可流式写入的 hash.Hash（实现 HMAC）。
// 未知算法名返回 ErrUnknownAlgorithm；opts 在本版未生效，保留供 0.4.0。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// New returns a streaming hash.Hash for the named algorithm (HMAC).
// Unknown names return ErrUnknownAlgorithm. opts is reserved for the
// 0.4.0 EVP_MAC_* migration and is currently ignored. It panics only
// if the underlying Tongsuo initialization fails, which does not occur
// in normal use.
func New(name string, key []byte, opts *Options) (hash.Hash, error) {
	_ = opts // reserved for 0.4.0
	a, err := lookup(name)
	if err != nil {
		return nil, err
	}
	return newHMAC(key, a.desc()), nil
}

// Sum 按算法名一次性计算 HMAC 并返回标签；未知算法名返回 ErrUnknownAlgorithm。
// opts 在本版未生效。
//
// Sum computes the HMAC tag for data in one shot under the named
// algorithm; unknown names return ErrUnknownAlgorithm. opts is reserved
// for the 0.4.0 EVP_MAC_* migration and is currently ignored.
func Sum(name string, key, data []byte, opts *Options) ([]byte, error) {
	_ = opts
	h, err := New(name, key, nil)
	if err != nil {
		return nil, err
	}
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("mac: %s: write: %w", name, err)
	}
	return h.Sum(nil), nil
}

// SumReader 按算法名从 r 流式计算 HMAC 标签直至 EOF；未知算法名返回
// ErrUnknownAlgorithm，读取失败返回底层错误（被包装）。本函数不关闭 r。
//
// SumReader streams r to its end and returns the HMAC tag for the named
// algorithm. Unknown names return ErrUnknownAlgorithm; read failures
// are returned wrapped. The reader is not closed.
func SumReader(name string, key []byte, r io.Reader, opts *Options) ([]byte, error) {
	_ = opts
	h, err := New(name, key, nil)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(h, r); err != nil {
		return nil, fmt.Errorf("mac: %s: read: %w", name, err)
	}
	return h.Sum(nil), nil
}

// newHMAC 包装 core.NewHmacCtx 为 hash.Hash。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// newHMAC wraps core.NewHmacCtx as hash.Hash. It panics only if the
// underlying Tongsuo initialization fails, which does not occur in
// normal use.
func newHMAC(key []byte, d *core.Digest) hash.Hash {
	ctx, err := core.NewHmacCtx(d, key)
	if err != nil {
		panic(err)
	}
	return &hmac{ctx: ctx, size: d.Size(), block: d.BlockSize()}
}

// hmac 实现标准 hash.Hash 接口的 HMAC 包装。
//
// hmac implements hash.Hash backed by Tongsuo's HMAC_CTX_* API.
type hmac struct {
	ctx   *core.HmacCtx
	size  int
	block int
}

// Write 追加数据，实现 io.Writer 与 hash.Hash。
//
// Write appends p and satisfies both io.Writer and hash.Hash.
func (h *hmac) Write(p []byte) (n int, err error) {
	if err := h.ctx.Update(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Sum 返回 HMAC 标签追加到 in 后，不改变内部状态。
//
// Sum appends the current HMAC tag to in without mutating state.
func (h *hmac) Sum(in []byte) []byte {
	sum, err := h.ctx.Sum()
	if err != nil {
		panic(err)
	}
	return append(in, sum...)
}

// Reset 重置 HMAC 状态（保留密钥与摘要算法）。
//
// Reset clears the HMAC state; the key and digest are kept.
func (h *hmac) Reset() {
	if err := h.ctx.Reset(); err != nil {
		panic(err)
	}
}

// Size 返回 HMAC 标签字节长度。
//
// Size returns the HMAC tag size in bytes.
func (h *hmac) Size() int { return h.size }

// BlockSize 返回 HMAC 内部分组字节长度。
//
// BlockSize returns the HMAC's internal block size in bytes.
func (h *hmac) BlockSize() int { return h.block }
