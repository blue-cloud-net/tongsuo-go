package sym

import (
	"fmt"
	"io"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// streamChunk 是流式加解密的输入分块大小（64 KiB）。
// 取 16 的整数倍，保证分组模式（ECB / CBC）在每个分块内都能整齐切分。
//
// streamChunk is the input chunk size for streaming encryption and
// decryption (64 KiB). It is a multiple of 16 so that the block modes
// (ECB / CBC) always split evenly inside a chunk.
const streamChunk = 64 << 10

// streamCipher 返回按名分发可用的流式描述符。
// 仅接受无填充的分组模式（ECB / CBC）与流模式（CTR / OFB / CFB / ChaCha20）；
// AEAD 模式（GCM / CCM / ChaCha20-Poly1305）与 XTS 需要一次性持有全部数据，
// 返回 ErrUnsupported。
//
// streamCipher returns the descriptor usable for streaming under the
// given name. Only unpadded block modes (ECB / CBC) and stream modes
// (CTR / OFB / CFB / ChaCha20) qualify; the AEAD modes (GCM / CCM /
// ChaCha20-Poly1305) and XTS need the whole input at once and return
// ErrUnsupported.
func streamCipher(name string, a algo, key []byte) (*core.Cipher, error) {
	switch a.mode {
	case "GCM", "CCM", "POLY1305", "XTS":
		return nil, fmt.Errorf("sym: %q: %w: streaming is not supported for this mode", name, ErrUnsupported)
	}
	if len(key) != a.size {
		return nil, fmt.Errorf("sym: %q: %w: got %d bytes, want %d",
			name, ErrInvalidKeyLength, len(key), a.size)
	}
	upper := strings.ToUpper(strings.TrimSpace(name))
	switch {
	case strings.HasPrefix(upper, "AES"):
		return aesCipher(key, strings.ToLower(a.mode))
	case strings.HasPrefix(upper, "SM4"):
		c := sm4Cipher(strings.ToLower(a.mode))
		if c == nil {
			return nil, fmt.Errorf("sym: %q: %w", name, ErrUnsupported)
		}
		return c, nil
	case a.mode == "STREAM":
		return core.ChaCha20(), nil
	}
	return nil, fmt.Errorf("sym: %q: %w", name, ErrUnknownAlgorithm)
}

// cryptSource 是 EncryptSource / DecryptSource 的共同实现：
// 打开 src → NewCipherCtx（PKCS#7 填充）→ 分块 Update → Final → 写入 sink。
// 任一步失败即返回包装错误，sink 与 src 的读取器由本函数负责关闭。
//
// cryptSource is the shared body of EncryptSource / DecryptSource: open
// src, create the context with PKCS#7 padding, feed it chunk by chunk,
// flush with Final and write everything to sink. Any failure returns a
// wrapped error; this function closes both the source reader and sink.
func cryptSource(name string, key, iv []byte, src *meta.Source, sink *meta.Sink, enc bool) error {
	a, _, err := lookup(name)
	if err != nil {
		return err
	}
	c, err := streamCipher(name, a, key)
	if err != nil {
		return err
	}
	ctx, err := core.NewCipherCtx(c, key, iv, enc)
	if err != nil {
		return err
	}
	defer ctx.Close()

	r, err := src.Open()
	if err != nil {
		return err
	}
	defer r.Close()

	buf := make([]byte, streamChunk)
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			out, upErr := ctx.Update(buf[:n])
			if upErr != nil {
				return upErr
			}
			if len(out) > 0 {
				if _, wErr := sink.Write(out); wErr != nil {
					return fmt.Errorf("sym: %s: write: %w", name, wErr)
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("sym: %s: read: %w", name, readErr)
		}
	}

	tail, err := ctx.Final()
	if err != nil {
		return err
	}
	if len(tail) > 0 {
		if _, err := sink.Write(tail); err != nil {
			return fmt.Errorf("sym: %s: write: %w", name, err)
		}
	}
	return nil
}

// EncryptSource 按「算法-模式」名流式加密 src 的全部内容并写入 sink。
// 仅支持无填充冲突的模式：ECB / CBC（PKCS#7 填充）、CTR / OFB / CFB /
// ChaCha20（流式，无需 IV 的模式传 nil）。AEAD 模式与 XTS 返回 ErrUnsupported。
// src 为 nil 等价于标准输入，sink 为 nil 等价于标准输出。
//
// EncryptSource streams everything src yields through the named
// algorithm-mode and writes the ciphertext to sink. Only modes that are
// safe to stream are accepted: ECB / CBC (PKCS#7 padding) and CTR / OFB /
// CFB / ChaCha20 (IV-less modes take a nil IV). The AEAD modes and XTS
// return ErrUnsupported. A nil src means standard input and a nil sink
// means standard output.
func EncryptSource(name string, key, iv []byte, src *meta.Source, sink *meta.Sink) error {
	return cryptSource(name, key, iv, src, sink, true)
}

// DecryptSource 按「算法-模式」名流式解密 src 的全部内容并写入 sink。
// 与 EncryptSource 支持的模式一致；解密失败（含 PKCS#7 填充校验失败）
// 返回包装 OpError 的错误，此时 sink 中可能已有部分明文写出。
// src 为 nil 等价于标准输入，sink 为 nil 等价于标准输出。
//
// DecryptSource streams everything src yields through the named
// algorithm-mode and writes the plaintext to sink. It accepts the same
// modes as EncryptSource; failures (including a bad PKCS#7 padding)
// return an error wrapping an OpError, in which case sink may already
// hold a prefix of the plaintext. A nil src means standard input and a
// nil sink means standard output.
func DecryptSource(name string, key, iv []byte, src *meta.Source, sink *meta.Sink) error {
	return cryptSource(name, key, iv, src, sink, false)
}
