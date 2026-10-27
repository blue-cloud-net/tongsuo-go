package meta

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Passphrase 是口令的来源抽象。
// 对应铜锁 CLI 的 `-passin` / `-passout`：`pass:` / `env:` / `file:` /
// `fd:` / `stdin` 五种来源。
//
// 口令在构造时即被读取（`stdin` 与 `fd:` 同理），因此构造完成后不再
// 依赖外部环境；口令内容**不会**出现在 String() 的输出里。
//
// Passphrase abstracts where a passphrase comes from, mirroring the
// Tongsuo CLI's -passin / -passout: the pass:, env:, file:, fd: and stdin
// sources.
//
// The passphrase is read eagerly at construction time (including for
// stdin and fd:), so the value no longer depends on the environment once
// the Passphrase exists; its content NEVER appears in the output of
// String().
type Passphrase struct {
	value []byte
	desc  string
}

// passphraseSchemes 是支持的来源前缀。
//
// passphraseSchemes lists the supported source prefixes.
var passphraseSchemes = []string{"pass", "env", "file", "fd", "stdin"}

// NewPassphrase 按来源说明构造口令。
// 说明形如 "pass:secret"、"env:NAME"、"file:/path"、"fd:3"、"stdin"。
// 不带前缀时整串按明文口令处理（等价于 "pass:"）。
// 未知前缀返回错误；来源不可读时返回底层错误。
//
// NewPassphrase builds a passphrase from a source specification.
// The specification looks like "pass:secret", "env:NAME", "file:/path",
// "fd:3" or "stdin". A specification without a prefix is taken as a
// literal passphrase (equivalent to "pass:"). An unknown prefix yields an
// error; an unreadable source yields the underlying error.
func NewPassphrase(spec string) (*Passphrase, error) {
	scheme, arg, hasPrefix := splitPassphraseSpec(spec)
	if !hasPrefix {
		scheme, arg = "pass", spec
	}
	switch scheme {
	case "pass":
		return &Passphrase{value: []byte(arg), desc: "pass:***"}, nil
	case "env":
		if arg == "" {
			return nil, fmt.Errorf("meta: empty environment variable name")
		}
		v, ok := os.LookupEnv(arg)
		if !ok {
			return nil, fmt.Errorf("meta: environment variable %q is not set", arg)
		}
		return &Passphrase{value: []byte(v), desc: "env:" + arg}, nil
	case "file":
		if arg == "" {
			return nil, fmt.Errorf("meta: empty passphrase file path")
		}
		data, err := os.ReadFile(arg)
		if err != nil {
			return nil, fmt.Errorf("meta: read passphrase file %q: %w", arg, err)
		}
		return &Passphrase{value: trimPassphraseNewline(data), desc: "file:***"}, nil
	case "fd":
		fd, err := strconv.Atoi(strings.TrimSpace(arg))
		if err != nil {
			return nil, fmt.Errorf("meta: invalid file descriptor %q", arg)
		}
		f := os.NewFile(uintptr(fd), "passphrase-fd")
		if f == nil {
			return nil, fmt.Errorf("meta: invalid file descriptor %d", fd)
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("meta: read passphrase from fd %d: %w", fd, err)
		}
		return &Passphrase{value: trimPassphraseNewline(data), desc: "fd:***"}, nil
	case "stdin":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("meta: read passphrase from stdin: %w", err)
		}
		return &Passphrase{value: trimPassphraseNewline(data), desc: "stdin:***"}, nil
	}
	return nil, fmt.Errorf("meta: unknown passphrase source %q", scheme)
}

// splitPassphraseSpec 把说明拆成来源前缀与参数。
// 第三个返回值报告是否确实带前缀（"pass:" 之外的未知前缀也会被识别，
// 由调用方判定合法性）。
//
// splitPassphraseSpec splits a specification into its source prefix and
// argument. The third result reports whether a prefix was present; an
// unknown prefix is still reported as a prefix so the caller can reject
// it.
func splitPassphraseSpec(spec string) (scheme, arg string, hasPrefix bool) {
	idx := strings.Index(spec, ":")
	if idx < 0 {
		return "", spec, false
	}
	head := strings.ToLower(strings.TrimSpace(spec[:idx]))
	for _, s := range passphraseSchemes {
		if head == s {
			return head, spec[idx+1:], true
		}
	}
	// 未知前缀：保留原样交给调用方报错。
	return head, spec[idx+1:], true
}

// trimPassphraseNewline 去掉口令末尾的换行（CLI 的 file:/fd: 语义）。
//
// trimPassphraseNewline removes the trailing newline of a passphrase
// (the CLI's file: / fd: semantics).
func trimPassphraseNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// Bytes 返回口令字节的副本。
// 调用方负责在用毕后清零该副本。
//
// Bytes returns a copy of the passphrase bytes. The caller is responsible
// for clearing that copy once it is no longer needed.
func (p *Passphrase) Bytes() []byte {
	if p == nil {
		return nil
	}
	return append([]byte(nil), p.value...)
}

// String 返回口令来源的脱敏描述，绝不包含口令内容。
//
// String returns a redacted description of the passphrase source; it never
// contains the passphrase itself.
func (p *Passphrase) String() string {
	if p == nil {
		return ""
	}
	return p.desc
}

// IsEmpty 报告口令是否为空。
//
// IsEmpty reports whether the passphrase is empty.
func (p *Passphrase) IsEmpty() bool {
	return p == nil || len(p.value) == 0
}
