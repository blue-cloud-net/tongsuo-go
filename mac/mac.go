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

// ErrInvalidOptions 表示按名入口缺少该算法必需的参数
// （如 CMAC 未给出底层分组算法、EIA3 未给出计数器）。
//
// ErrInvalidOptions reports that a by-name entry was given a parameter
// set that lacks something the algorithm requires (for example CMAC
// without an underlying block cipher, or EIA3 without its counter).
var ErrInvalidOptions = errors.New("mac: invalid options")

// Options 覆盖 MAC 算法的可选参数。
// 全部字段均为「不指定即用默认值」——置零值即可。
//
// 字段语义映射铜锁 CLI 的 -macopt：
//
//	Cipher    → -macopt cipher:<name>      （CMAC / GMAC 时必填）
//	IV        → -macopt hexiv:<hex>        （GMAC / EIA3 时必填）
//	AAD       → -macopt aad:<hex>          （GMAC 时使用）
//	Custom    → -macopt custom:<hex>       （KMAC 时使用）
//	OutputLen → -macopt size:<bytes>       （KMAC / SipHash 时使用）
//	Digest    → 覆盖 HMAC 的底层摘要算法名
//
// Options holds optional MAC algorithm parameters. Zero values mean
// "use the default". Field semantics map to Tongsuo CLI -macopt keys;
// see the per-field comments.
//
// Cipher names may be given in the short form ("SM4", "AES-128",
// "AES-192", "AES-256"), in which case the mode suffix required by the
// algorithm is appended automatically ("SM4-CBC" for CMAC, "SM4-GCM" for
// GMAC).
type Options struct {
	// Cipher 指定 CMAC / GMAC 用的底层分组算法名。
	// CMAC 需要 CBC 模式（"SM4"、"AES-128" 等短名会自动补 "-CBC"）；
	// GMAC 需要 GCM 模式（短名会自动补 "-GCM"）。
	//
	// Cipher selects the underlying block cipher used by CMAC / GMAC.
	// CMAC requires a CBC-mode cipher (the short names get "-CBC"
	// appended automatically); GMAC requires a GCM-mode cipher (the
	// short names get "-GCM" appended automatically).
	Cipher string
	// IV 是 GMAC 的初始向量（nil/空表示让铜锁生成默认 IV）。
	// 对 GMAC 而言该值就是 nonce，必须与加密侧一致。
	//
	// IV is the initialization vector for GMAC (nil/empty lets Tongsuo
	// pick one). For GMAC this value is the nonce and MUST match the
	// one used on the encrypting side.
	IV []byte
	// AAD 是 GMAC 的附加认证数据（authenticated but not encrypted）；
	// 初始化后会先于业务数据送入。
	//
	// AAD holds Additional Authenticated Data for GMAC; it is fed
	// before the payload right after initialisation.
	AAD []byte
	// Custom 是 KMAC 的 customization 串。
	//
	// Custom is the KMAC customization string.
	Custom []byte
	// OutputLen 指定输出字节数（0 表示按算法默认；KMAC 必须显式指定）。
	//
	// OutputLen is the requested output size in bytes (0 = default).
	OutputLen int
	// Digest 覆盖 HMAC 的底层摘要算法名（如 "SHA256"）。
	// 为空时按算法名隐含的摘要执行。
	//
	// Digest overrides the underlying message-digest name of HMAC (for
	// example "SHA256"). When empty, the digest implied by the
	// algorithm name is used.
	Digest string
}

// algo 描述一个已支持的 MAC 算法。
//
// algo describes one supported MAC algorithm.
type algo struct {
	// name 是按名分发名（大小写不敏感）。
	//
	// name is the by-name dispatch name (case-insensitive).
	name string
	// provider 是 provider 侧的算法名。
	//
	// provider is the provider-side algorithm name.
	provider string
	// tag 是标签长度（0 表示由参数或 provider 决定）。
	//
	// tag is the tag size (0 means it is decided by the options or the
	// provider).
	tag int
	// block 是内部分组长度。
	//
	// block is the internal block size.
	block int
	// digest 是 HMAC 家族隐含的底层摘要算法名。
	//
	// digest is the message-digest name implied by the HMAC family.
	digest string
	// needCipher 表示必须给出底层分组算法名。
	//
	// needCipher marks the algorithms that require a cipher name.
	needCipher bool
	// needIV 表示必须给出初始向量。
	//
	// needIV marks the algorithms that require an initialization vector.
	needIV bool
	// needCustom 表示可给出 customization 串（KMAC）。
	//
	// needCustom marks the algorithms that accept a customization
	// string (KMAC).
	needCustom bool
	// needSize 表示可给出输出长度（KMAC / SipHash）。
	//
	// needSize marks the algorithms that accept an output size
	// (KMAC / SipHash).
	needSize bool
}

// algos 是算法注册表；切片顺序即 Names() 的返回顺序（稳定）。
// HMAC 系列在前（保持既有顺序），其余家族在后。
//
// algos is the algorithm registry; the slice order defines the stable
// order returned by Names(). The HMAC family comes first (keeping the
// pre-existing order), the remaining families follow.
var algos = []algo{
	{"HMAC-SM3", "HMAC", 32, 64, "SM3", false, false, false, false},
	{"HMAC-MD5", "HMAC", 16, 64, "MD5", false, false, false, false},
	{"HMAC-SHA1", "HMAC", 20, 64, "SHA1", false, false, false, false},
	{"HMAC-SHA224", "HMAC", 28, 64, "SHA224", false, false, false, false},
	{"HMAC-SHA256", "HMAC", 32, 64, "SHA256", false, false, false, false},
	{"HMAC-SHA384", "HMAC", 48, 128, "SHA384", false, false, false, false},
	{"HMAC-SHA512", "HMAC", 64, 128, "SHA512", false, false, false, false},
	{"CMAC", "CMAC", 16, 16, "", true, false, false, false},
	{"GMAC", "GMAC", 16, 16, "", true, true, false, false},
	{"KMAC-128", "KMAC-128", 32, 168, "", false, false, true, true},
	{"KMAC-256", "KMAC-256", 64, 168, "", false, false, true, true},
	{"SIPHASH", "SIPHASH", 16, 8, "", false, false, false, true},
	{"POLY1305", "POLY1305", 16, 16, "", false, false, false, false},
	{"EIA3", "EIA3", 4, 4, "", false, true, false, false},
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
// HMAC-SHA384 / HMAC-SHA512 / CMAC / GMAC / KMAC-128 / KMAC-256 /
// SIPHASH / POLY1305 / EIA3）。
//
// Names returns the MAC algorithm names supported by this version in a
// stable order (HMAC-SM3 / HMAC-MD5 / HMAC-SHA1 / HMAC-SHA224 /
// HMAC-SHA256 / HMAC-SHA384 / HMAC-SHA512 / CMAC / GMAC / KMAC-128 /
// KMAC-256 / SIPHASH / POLY1305 / EIA3).
func Names() []string {
	out := make([]string, len(algos))
	for i, a := range algos {
		out[i] = a.name
	}
	return out
}

// cipherMode 返回某算法要求底层分组算法所处的模式（"CBC" / "GCM"）。
// 不需要底层分组算法的算法返回空串。
//
// cipherMode returns the mode the underlying block cipher must be in for
// the given algorithm ("CBC" / "GCM"). It returns an empty string for the
// algorithms that do not use a block cipher.
func (a algo) cipherMode() string {
	switch a.provider {
	case "CMAC":
		return "CBC"
	case "GMAC":
		return "GCM"
	}
	return ""
}

// normalizeCipher 把底层分组算法名归一为 provider 可解析的形式。
// 短名（"SM4" / "AES-128" / "AES-192" / "AES-256"）按 mode 补齐后缀；
// 其余名字原样透传。
//
// normalizeCipher normalises a cipher name into a form the provider can
// resolve. The short names ("SM4" / "AES-128" / "AES-192" / "AES-256")
// get the mode suffix appended; other names are passed through.
func normalizeCipher(name, mode string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || mode == "" {
		return trimmed
	}
	upper := strings.ToUpper(trimmed)
	switch upper {
	case "SM4", "AES-128", "AES-192", "AES-256":
		return upper + "-" + mode
	}
	return trimmed
}

// coreOptions 把公开 Options 转成核心层参数包，并校验必填项。
//
// coreOptions converts the public Options into the core-layer parameter
// bundle and validates the mandatory fields.
func (a algo) coreOptions(opts *Options) (*core.MACOptions, error) {
	var o core.MACOptions
	if opts != nil {
		if opts.Cipher != "" {
			o.Cipher = normalizeCipher(opts.Cipher, a.cipherMode())
		}
		o.IV = opts.IV
		o.AAD = opts.AAD
		o.Custom = opts.Custom
		o.OutputLen = opts.OutputLen
		o.Digest = opts.Digest
	}
	if a.digest != "" && o.Digest == "" {
		o.Digest = a.digest
	}
	if a.needCipher && o.Cipher == "" {
		return nil, fmt.Errorf("mac: %s: %w: Cipher is required", a.name, ErrInvalidOptions)
	}
	if a.needIV && len(o.IV) == 0 {
		return nil, fmt.Errorf("mac: %s: %w: IV is required", a.name, ErrInvalidOptions)
	}
	return &o, nil
}

// New 按算法名返回可流式写入的 hash.Hash。
// 未知算法名返回 ErrUnknownAlgorithm；缺少算法必需参数返回 ErrInvalidOptions。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// New returns a streaming hash.Hash for the named algorithm. Unknown
// names return ErrUnknownAlgorithm; a missing mandatory parameter
// returns ErrInvalidOptions. Failures surface as errors: the returned
// hash.Hash exposes Err() for the (error-less) Sum path.
func New(name string, key []byte, opts *Options) (hash.Hash, error) {
	a, err := lookup(name)
	if err != nil {
		return nil, err
	}
	coreOpts, err := a.coreOptions(opts)
	if err != nil {
		return nil, err
	}
	desc, err := core.MACFetch(a.provider)
	if err != nil {
		return nil, fmt.Errorf("mac: %s: %w", a.name, err)
	}
	defer desc.Close()
	ctx, err := core.NewMACCtx(desc, key, coreOpts)
	if err != nil {
		return nil, fmt.Errorf("mac: %s: %w", a.name, err)
	}
	block := a.block
	if n := ctx.BlockSize(); n > 0 {
		block = n
	}
	h := &macHash{ctx: ctx, size: ctx.Size(), block: block}
	// 探测 EVP_MAC_CTX_dup：MACCtx.Sum 内部走 Dup，失败则本构建不可复制。
	// 失败时上下文保持不变，可安全继续使用。
	//
	// Probe EVP_MAC_CTX_dup: MACCtx.Sum duplicates the context, so a
	// failure means this build cannot copy it. The context is unchanged
	// on failure and stays usable.
	if _, err := ctx.Sum(); err != nil {
		h.replay = true
	}
	return h, nil
}

// Sum 按算法名一次性计算 MAC 标签。
// 未知算法名返回 ErrUnknownAlgorithm；缺少算法必需参数返回 ErrInvalidOptions。
//
// Sum computes the MAC tag for data in one shot under the named
// algorithm. Unknown names return ErrUnknownAlgorithm; a missing
// mandatory parameter returns ErrInvalidOptions.
func Sum(name string, key, data []byte, opts *Options) ([]byte, error) {
	h, err := New(name, key, opts)
	if err != nil {
		return nil, err
	}
	defer closeHash(h)
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("mac: %s: write: %w", name, err)
	}
	tag := h.Sum(nil)
	if err := sumErr(h); err != nil {
		return nil, fmt.Errorf("mac: %s: %w", name, err)
	}
	return tag, nil
}

// SumReader 按算法名从 r 流式计算 MAC 标签直至 EOF。
// 未知算法名返回 ErrUnknownAlgorithm；读取失败返回底层错误（被包装）。
// 本函数不关闭 r。
//
// SumReader streams r to its end and returns the MAC tag for the named
// algorithm. Unknown names return ErrUnknownAlgorithm; read failures are
// returned wrapped. The reader is not closed.
func SumReader(name string, key []byte, r io.Reader, opts *Options) ([]byte, error) {
	h, err := New(name, key, opts)
	if err != nil {
		return nil, err
	}
	defer closeHash(h)
	if _, err := io.Copy(h, r); err != nil {
		return nil, fmt.Errorf("mac: %s: read: %w", name, err)
	}
	tag := h.Sum(nil)
	if err := sumErr(h); err != nil {
		return nil, fmt.Errorf("mac: %s: %w", name, err)
	}
	return tag, nil
}

// sumErr 取出 hash.Hash 背后的 MAC 失败原因（仅 *macHash 提供）。
// hash.Hash.Sum 无错误返回位，因此一次性入口在 Sum 之后必须回查一次，
// 否则失败会被静默吞掉。
//
// sumErr extracts the MAC failure behind a hash.Hash (only *macHash
// exposes it). hash.Hash.Sum has no error return, so the one-shot entries
// must check back after calling it or a failure would be swallowed.
func sumErr(h hash.Hash) error {
	if mh, ok := h.(*macHash); ok {
		return mh.Err()
	}
	return nil
}

// closeHash 释放 hash.Hash 底层的 MAC 上下文（若实现了关闭接口）。
//
// closeHash releases the MAC context behind a hash.Hash when it exposes
// a close method.
func closeHash(h hash.Hash) {
	if c, ok := h.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

// macHash 实现标准 hash.Hash 接口的 MAC 包装。
// 部分构建（典型如 Tongsuo 8.4.0 的 GMAC）不支持 EVP_MAC_CTX_dup，
// 此时无法在「不破坏状态」的前提下取标签；本类型会在构造时探测该能力，
// 不可复制时改为缓冲写入数据并在 Sum 时重算（内存开销仅限这类构建）。
//
// macHash implements hash.Hash backed by Tongsuo's EVP_MAC_* API. Some
// builds (notably GMAC on Tongsuo 8.4.0) do not support
// EVP_MAC_CTX_dup, so the tag cannot be read without destroying the
// state. This type probes that capability at construction time and, when
// duplication is unavailable, buffers the written data and recomputes on
// Sum (the memory cost applies only to such builds).
type macHash struct {
	ctx   *core.MACCtx
	size  int
	block int
	// replay 为 true 时按缓冲重算（本构建不支持 CTX_dup）。
	//
	// replay selects the buffered recompute path when CTX_dup is
	// unavailable.
	replay bool
	buf    []byte
	// err 记录最近一次失败，供调用方通过 Err 查询（Sum 不返回 error）。
	//
	// err keeps the most recent failure for Err (Sum returns no error).
	err error
}

// Err 返回最近一次 Sum / Reset 失败的原因，无失败时返回 nil。
// 只有具体类型 *macHash 提供该方法；New 返回的 hash.Hash 可用类型断言获取。
// 之所以不 panic：本库约定库内不得 panic，而 hash.Hash.Sum 无错误返回位。
//
// Err returns the cause of the most recent Sum / Reset failure, or nil.
// Only the concrete *macHash exposes it; callers of New's hash.Hash can
// obtain it through a type assertion. It exists because hash.Hash.Sum has
// no error return and this library never panics.
func (h *macHash) Err() error { return h.err }

// Write 追加数据，实现 io.Writer 与 hash.Hash。
//
// Write appends p and satisfies both io.Writer and hash.Hash.
func (h *macHash) Write(p []byte) (int, error) {
	if err := h.ctx.Update(p); err != nil {
		return 0, err
	}
	if h.replay {
		h.buf = append(h.buf, p...)
	}
	return len(p), nil
}

// Sum 返回 MAC 标签追加到 in 后，不改变内部状态。
// 失败时不写入任何字节，失败原因可通过 Err 查询。
//
// Sum appends the current MAC tag to in without mutating state. On
// failure nothing is appended and the cause is available via Err.
func (h *macHash) Sum(in []byte) []byte {
	var (
		sum []byte
		err error
	)
	if h.replay {
		sum, err = h.recompute()
	} else {
		sum, err = h.ctx.Sum()
	}
	if err != nil {
		h.err = err
		return in
	}
	return append(in, sum...)
}

// recompute 在 dup 不可用的构建上按缓冲重算标签：
// 重置 → 重放缓冲 → Final，然后再重置并把缓冲重新喂回去，
// 使调用方可以继续 Write（hash.Hash 的 Sum 不得改变状态）。
//
// recompute produces the tag on builds without CTX_dup: reset, replay
// the buffer, Final, then reset and replay again so the caller can keep
// writing (hash.Hash's Sum must not mutate state).
func (h *macHash) recompute() ([]byte, error) {
	if err := h.rewind(); err != nil {
		return nil, err
	}
	tag, err := h.ctx.Final()
	if err != nil {
		return nil, err
	}
	if err := h.rewind(); err != nil {
		return nil, err
	}
	return tag, nil
}

// rewind 重置上下文并把已写入的数据重新喂回。
//
// rewind resets the context and replays the buffered data.
func (h *macHash) rewind() error {
	if err := h.ctx.Reset(); err != nil {
		return err
	}
	if len(h.buf) == 0 {
		return nil
	}
	return h.ctx.Update(h.buf)
}

// Reset 重置 MAC 状态（保留密钥与算法参数）。
// 失败原因可通过 Err 查询。
//
// Reset clears the MAC state; the key and algorithm parameters are kept.
// The cause of a failure is available via Err.
func (h *macHash) Reset() {
	h.buf = h.buf[:0]
	if err := h.ctx.Reset(); err != nil {
		h.err = err
	}
}

// Size 返回 MAC 标签字节长度。
//
// Size returns the MAC tag size in bytes.
func (h *macHash) Size() int { return h.size }

// BlockSize 返回 MAC 的内部分组字节长度。
//
// BlockSize returns the MAC's internal block size in bytes.
func (h *macHash) BlockSize() int { return h.block }

// Close 释放底层 MAC 上下文。幂等。
//
// Close releases the underlying MAC context. The call is idempotent.
func (h *macHash) Close() error {
	return h.ctx.Close()
}
