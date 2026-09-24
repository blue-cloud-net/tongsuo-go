package meta

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// ErrorString 返回铜锁错误码对应的文本描述。
// 等价 tongsuo errstr <code>，底层调 native.ErrorString（包装
// ERR_error_string_n）。未知错误码返回 "<code hex>:" 占位文本（不 panic）。
//
// ErrorString returns the human-readable description of a Tongsuo
// error code. It matches `tongsuo errstr <code>` and wraps
// ERR_error_string_n via native.ErrorString. Unknown codes resolve to
// a "<hex>:" placeholder rather than panicking.
func ErrorString(code uint64) string {
	return native.ErrorString(code)
}

// ErrorCode 尝试从 error 链中提取铜锁错误码。
// 识别 *core.OpError（直接持有 Code 字段）；对 fmt.Errorf("...: %w", err)
// 包装链也逐层向下查找。找到返回 (code, true)；未找到返回 (0, false)。
// 本函数不识别原生 net.Error 等「无错误码」的 error 类型——这是预期行为，
// 因为 net.Error 与密码学错误码语义不重叠。
//
// ErrorCode extracts a Tongsuo error code from an error chain.
// It recognises *core.OpError (which carries the code directly) and
// walks fmt.Errorf("...: %w", err) chains recursively. On success
// returns (code, true); otherwise (0, false). Errors without an
// attached native code (e.g. net.Error) are intentionally not
// recognised — the two error families do not overlap.
func ErrorCode(err error) (uint64, bool) {
	for err != nil {
		var oe *core.OpError
		if errors.As(err, &oe) {
			return oe.Code, true
		}
		err = errors.Unwrap(err)
	}
	return 0, false
}

// ParseErrorCode 解析多种格式的错误码字符串。
// 支持的格式：
//   - "0x0906D06C" / "0X0906D06C" 十六进制（与 tongsuo errstr 输入一致）
//   - "184428"                     十进制
//   - "0906D06C" / "0906D06c"      无前缀的十六进制（兜底）
//
// 解析失败返回 error；空串与不识别格式同样返回 error。
//
// ParseErrorCode parses an error-code string in several formats:
//   - "0x0906D06C" / "0X0906D06C"  hex (matches `tongsuo errstr` input)
//   - "184428"                     decimal
//   - "0906D06C" / "0906D06c"      unprefixed hex (fallback)
//
// Returns an error on empty input, unrecognised format or overflow.
//
// 不支持反向解析 tongsuo errstr 输出里的 "lib(N)::reason(M)"——
// OpenSSL 3.x 的 lib/reason 打包与 ERR_PACK 不一一对应，需要查内部表。
//
// Reverse-parsing the "lib(N)::reason(M)" form from `tongsuo errstr`
// output is NOT supported; OpenSSL 3.x lib/reason packing does not
// map 1:1 onto ERR_PACK and requires an internal lookup table.
func ParseErrorCode(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("meta: ParseErrorCode: empty input")
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("meta: ParseErrorCode: hex parse %q: %w", s, err)
		}
		return v, nil
	}
	if v, err := strconv.ParseUint(s, 10, 64); err == nil {
		return v, nil
	}
	if v, err := strconv.ParseUint(s, 16, 64); err == nil {
		return v, nil
	}
	return 0, fmt.Errorf("meta: ParseErrorCode: unrecognised format %q", s)
}
