package digest

import (
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	extdigest "github.com/blue-cloud-net/tongsuo-go/internal/digest"
)

// 摘要长度常量（字节）。常量名带算法前缀，避免合并后重名。
//
// Digest length constants in bytes. Each name carries its algorithm
// prefix to avoid collisions after the five legacy packages merged.
const (
	// SM3Size 为 SM3 摘要的字节长度（32 字节 / 256 位）。
	//
	// SM3Size is the byte length of an SM3 digest (256 bits).
	SM3Size = 32
	// SM3BlockSize 为 SM3 内部分组的字节长度。
	//
	// SM3BlockSize is the internal block size in bytes of SM3.
	SM3BlockSize = 64

	// MD5Size 为 MD5 摘要的字节长度（16 字节 / 128 位）。
	//
	// MD5Size is the byte length of an MD5 digest (128 bits).
	MD5Size = 16
	// MD5BlockSize 为 MD5 内部分组的字节长度。
	//
	// MD5BlockSize is the internal block size in bytes of MD5.
	MD5BlockSize = 64

	// SHA1Size 为 SHA-1 摘要的字节长度（20 字节 / 160 位）。
	//
	// SHA1Size is the byte length of a SHA-1 digest (160 bits).
	SHA1Size = 20
	// SHA1BlockSize 为 SHA-1 内部分组的字节长度。
	//
	// SHA1BlockSize is the internal block size in bytes of SHA-1.
	SHA1BlockSize = 64

	// SHA224Size 为 SHA-224 摘要的字节长度（28 字节 / 224 位）。
	//
	// SHA224Size is the byte length of a SHA-224 digest (224 bits).
	SHA224Size = 28
	// SHA224BlockSize 为 SHA-224 内部分组的字节长度。
	//
	// SHA224BlockSize is the internal block size in bytes of SHA-224.
	SHA224BlockSize = 64

	// SHA256Size 为 SHA-256 摘要的字节长度（32 字节 / 256 位）。
	//
	// SHA256Size is the byte length of a SHA-256 digest (256 bits).
	SHA256Size = 32
	// SHA256BlockSize 为 SHA-256 内部分组的字节长度。
	//
	// SHA256BlockSize is the internal block size in bytes of SHA-256.
	SHA256BlockSize = 64

	// SHA384Size 为 SHA-384 摘要的字节长度（48 字节 / 384 位）。
	//
	// SHA384Size is the byte length of a SHA-384 digest (384 bits).
	SHA384Size = 48
	// SHA384BlockSize 为 SHA-384 内部分组的字节长度（128 字节，SHA-512 家族）。
	//
	// SHA384BlockSize is the internal block size in bytes of SHA-384
	// (128 bytes, matching the SHA-512 family).
	SHA384BlockSize = 128

	// SHA512Size 为 SHA-512 摘要的字节长度（64 字节 / 512 位）。
	//
	// SHA512Size is the byte length of a SHA-512 digest (512 bits).
	SHA512Size = 64
	// SHA512BlockSize 为 SHA-512 内部分组的字节长度。
	//
	// SHA512BlockSize is the internal block size in bytes of SHA-512.
	SHA512BlockSize = 128
)

// ErrUnknownAlgorithm 表示按算法名分发时传入的名称不在 Names() 内。
// 按名入口返回的错误均可用 errors.Is(err, ErrUnknownAlgorithm) 判定。
//
// ErrUnknownAlgorithm reports that a by-name entry was given a name not
// present in Names(). Errors from the by-name entries can be tested with
// errors.Is(err, ErrUnknownAlgorithm).
var ErrUnknownAlgorithm = errors.New("digest: unknown algorithm")

// algo 描述一个已支持的摘要算法：名称、尺寸、分组长度与核心层工厂函数。
//
// algo describes one supported digest algorithm: its name, digest size,
// block size and the core-layer descriptor factory.
type algo struct {
	name  string
	size  int
	block int
	desc  func() *core.Digest
}

// algos 是算法注册表；切片顺序即 Names() 的返回顺序（稳定）。
//
// algos is the algorithm registry; the slice order defines the stable
// order returned by Names().
var algos = []algo{
	{"SM3", SM3Size, SM3BlockSize, core.SM3},
	{"MD5", MD5Size, MD5BlockSize, core.MD5},
	{"SHA1", SHA1Size, SHA1BlockSize, core.SHA1},
	{"SHA224", SHA224Size, SHA224BlockSize, core.SHA224},
	{"SHA256", SHA256Size, SHA256BlockSize, core.SHA256},
	{"SHA384", SHA384Size, SHA384BlockSize, core.SHA384},
	{"SHA512", SHA512Size, SHA512BlockSize, core.SHA512},
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
	return algo{}, fmt.Errorf("digest: %q: %w", name, ErrUnknownAlgorithm)
}

// Names 返回本版支持的摘要算法名，顺序稳定（SM3、MD5、SHA1、SHA224、SHA256、
// SHA384、SHA512）。
//
// Names returns the digest algorithm names supported by this version in
// a stable order (SM3, MD5, SHA1, SHA224, SHA256, SHA384, SHA512).
func Names() []string {
	out := make([]string, len(algos))
	for i, a := range algos {
		out[i] = a.name
	}
	return out
}

// Size 返回指定算法的摘要字节长度；未知算法名返回 ErrUnknownAlgorithm。
//
// Size returns the digest length in bytes for the named algorithm, or
// ErrUnknownAlgorithm when the name is not registered.
func Size(name string) (int, error) {
	a, err := lookup(name)
	if err != nil {
		return 0, err
	}
	return a.size, nil
}

// BlockSize 返回指定算法的内部分组字节长度；未知算法名返回 ErrUnknownAlgorithm。
//
// BlockSize returns the internal block length in bytes for the named
// algorithm, or ErrUnknownAlgorithm when the name is not registered.
func BlockSize(name string) (int, error) {
	a, err := lookup(name)
	if err != nil {
		return 0, err
	}
	return a.block, nil
}

// New 按算法名返回可流式写入的 hash.Hash；未知算法名返回 ErrUnknownAlgorithm。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// New returns a streaming hash.Hash for the named algorithm, or
// ErrUnknownAlgorithm when the name is not registered. It panics only if
// the underlying Tongsuo initialization fails, which does not occur in
// normal use.
func New(name string) (hash.Hash, error) {
	a, err := lookup(name)
	if err != nil {
		return nil, err
	}
	return extdigest.NewHash(a.desc(), a.size, a.block), nil
}

// Sum 按算法名一次性计算 data 的摘要，返回的切片长度等于该算法的 Size；
// 未知算法名返回 ErrUnknownAlgorithm。
//
// Sum computes the digest of data in one shot for the named algorithm.
// The returned slice has the algorithm's Size; unknown names return
// ErrUnknownAlgorithm.
func Sum(name string, data []byte) ([]byte, error) {
	a, err := lookup(name)
	if err != nil {
		return nil, err
	}
	sum, err := a.desc().OneShot(data)
	if err != nil {
		return nil, fmt.Errorf("digest: %s: one-shot: %w", a.name, err)
	}
	return sum, nil
}

// SumReader 按算法名从 r 流式计算摘要直至 EOF，返回长度等于该算法 Size 的
// 切片；未知算法名返回 ErrUnknownAlgorithm，读取失败返回底层错误。
// 本函数不关闭 r。
//
// SumReader streams r to its end and returns the digest for the named
// algorithm (length equals the algorithm's Size). Unknown names return
// ErrUnknownAlgorithm; read failures are wrapped and returned. The
// reader is not closed.
func SumReader(name string, r io.Reader) ([]byte, error) {
	h, err := New(name)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(h, r); err != nil {
		return nil, fmt.Errorf("digest: %s: read: %w", name, err)
	}
	return h.Sum(nil), nil
}
