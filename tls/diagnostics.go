package tls

import (
	"fmt"
	"io"
	"sync"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// ErrUnsupported 表示显式请求的原生 TLS 能力不可用。
//
// ErrUnsupported indicates an explicitly requested native TLS capability is unavailable.
var ErrUnsupported = core.ErrTLSUnsupported

// ErrDiagnosticLimit 表示诊断暂存超过配置限额。
//
// ErrDiagnosticLimit indicates buffered diagnostics exceeded the configured limit.
var ErrDiagnosticLimit = core.ErrTLSLimit

// HandshakeEvent 为连接内有序的独立诊断副本，不包含 keylog。
//
// HandshakeEvent is an ordered independent diagnostic copy without keylog material.
type HandshakeEvent struct {
	// AlertLevel 为 Alert 级别，其他事件为零。
	//
	// AlertLevel is the Alert level, zero for other events.
	AlertLevel int
	// AlertDescription 为 Alert 描述码，其他事件为零。
	//
	// AlertDescription is the Alert description code, zero for other events.
	AlertDescription int
	// Sequence 从一开始，按连接递增。
	//
	// Sequence starts at one and increases per connection.
	Sequence uint64
	// Kind 为 start、end、state、message、alert、verify 或 verify_callback。
	//
	// Kind is start, end, state, message, alert, verify or verify_callback.
	Kind string
	// Write 标记发送方向。
	//
	// Write identifies outgoing observations.
	Write bool
	// Version 保存原生协议版本。
	//
	// Version holds the native protocol version.
	Version int
	// ContentType 保存原生消息类型或状态标志。
	//
	// ContentType holds the native message type or state flags.
	ContentType int
	// Code 保存原生状态、验证码或 Alert 编码。
	//
	// Code holds a native result, verification code or encoded Alert.
	Code int
	// Depth 为证书验证深度。
	//
	// Depth is the certificate verification depth.
	Depth int
	// Data 为可保留的独立字节副本。
	//
	// Data is an independent byte copy that may be retained.
	Data []byte
	// Err 保存握手结束或自定义验证错误。
	//
	// Err holds a handshake completion or custom verification error.
	Err error
}

// DiagnosticsConfig 配置同步诊断。消费者不得重入同一连接，必须及时返回。
// 慢消费者会延迟连接操作；错误、短写与超限中断连接。共享 Writer 由调用方同步。
// KeyLogWriter 输出会话密钥，仅供显式诊断使用，调用方负责保护输出。
//
// DiagnosticsConfig configures synchronous diagnostics. Consumers must return promptly
// and must not reenter the connection. Slow consumers delay operations; errors, short
// writes and limits abort the connection. Callers synchronize shared writers and
// protect session secrets explicitly written to KeyLogWriter.
type DiagnosticsConfig struct {
	// OnEvent 接收事件副本，可保留数据；返回错误中断连接。
	//
	// OnEvent receives retainable copies; returning an error aborts the connection.
	OnEvent func(HandshakeEvent) error
	// TraceWriter 接收原生解码文本，nil 关闭。
	//
	// TraceWriter receives native decoded text; nil disables it.
	TraceWriter io.Writer
	// KeyLogWriter 接收原生 keylog 行，nil 关闭。
	//
	// KeyLogWriter receives native keylog lines; nil disables it.
	KeyLogWriter io.Writer
	// MaxEvents 为每次派发事件上限，零值使用 256，负值非法。
	//
	// MaxEvents limits observations per dispatch; zero selects 256, negatives are invalid.
	MaxEvents int
	// MaxBytes 为每次派发字节上限，零值使用 1 MiB，负值非法。
	//
	// MaxBytes limits bytes per dispatch; zero selects 1 MiB, negatives are invalid.
	MaxBytes int
}

const (
	defaultDiagnosticMaxEvents = 256
	defaultDiagnosticMaxBytes  = 1 << 20
)

type diagnosticDelivery struct {
	mu       sync.Mutex
	config   DiagnosticsConfig
	sequence uint64
	err      error
}

func (d *diagnosticDelivery) event(e HandshakeEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	if d.config.OnEvent == nil {
		return nil
	}
	d.sequence++
	e.Sequence = d.sequence
	d.err = d.config.OnEvent(e)
	return d.err
}
func (d *diagnosticDelivery) observe(e core.TLSEvent) error {
	if e.Kind == 6 || e.Kind == 7 {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.err != nil {
			return d.err
		}
		writer, data := d.config.TraceWriter, e.Data
		if e.Kind == 7 {
			writer = d.config.KeyLogWriter
			data = append(data, '\n')
		}
		if writer == nil {
			return nil
		}
		n, err := writer.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		if err != nil {
			d.err = fmt.Errorf("tls: diagnostic writer: %w", err)
		}
		return d.err
	}
	kinds := map[int]string{0: "start", 1: "end", 9: "verify_callback", 2: "state", 3: "message", 4: "alert", 5: "verify"}
	level, description := 0, 0
	if e.Kind == 4 {
		level, description = (e.Code>>8)&255, e.Code&255
	}
	return d.event(HandshakeEvent{Err: e.Err, AlertLevel: level, AlertDescription: description, Kind: kinds[e.Kind], Write: e.Write, Version: e.Version, ContentType: e.Type, Code: e.Code, Depth: e.Depth, Data: e.Data})
}
