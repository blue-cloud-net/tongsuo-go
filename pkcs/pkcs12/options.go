package pkcs12

import (
	"fmt"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// Options 配置 PKCS#12 编码与改密；ReadPass 用于输入，WritePass 用于输出。
// 口令不得含 NUL；PBE 不会启用 legacy provider。
//
// Options configures PKCS#12 encoding and password changes; ReadPass opens input and WritePass protects output.
// Passwords must not contain NUL; PBE never enables the legacy provider.
type Options struct {
	// PBE 为 AES-128/192/256-CBC 或 PBE-SHA1-3DES；空为 AES-256-CBC。
	//
	// PBE is AES-128/192/256-CBC or PBE-SHA1-3DES; empty selects AES-256-CBC.
	PBE string
	// Iterations 为加密与 MAC 迭代次数；0 为 2048，负值无效。
	//
	// Iterations sets encryption and MAC iterations; zero means 2048, negatives are invalid.
	Iterations int
	// FriendlyName 为容器友好名称。
	//
	// FriendlyName is the container's friendly name.
	FriendlyName string
	// ReadPass 为输入容器口令。
	//
	// ReadPass is the input container password.
	ReadPass string
	// WritePass 为输出容器口令。
	//
	// WritePass is the output container password.
	WritePass string
}

func normalizeOptions(opts *Options) (Options, error) {
	o := Options{}
	if opts != nil {
		o = *opts
	}
	if o.Iterations == 0 {
		o.Iterations = 2048
	}
	if o.Iterations < 1 || int64(o.Iterations) > 2147483647 {
		return o, fmt.Errorf("pkcs12: invalid iteration count")
	}
	o.PBE = strings.ToUpper(o.PBE)
	switch o.PBE {
	case "":
		o.PBE = "AES-256-CBC"
	case "AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "PBE-SHA1-3DES":
	default:
		return o, fmt.Errorf("pkcs12: unsupported PBE %q", o.PBE)
	}
	for _, s := range []string{o.FriendlyName, o.ReadPass, o.WritePass} {
		if strings.ContainsRune(s, 0) {
			return o, fmt.Errorf("pkcs12: NUL in name or password")
		}
	}
	return o, nil
}

// ParseWithOptions 使用 ReadPass 解析容器；返回资源由调用方负责释放。
//
// ParseWithOptions parses a container using ReadPass; callers must release returned resources.
func ParseWithOptions(data []byte, opts *Options) (*Bundle, error) {
	o, err := normalizeOptions(opts)
	if err != nil {
		return nil, err
	}
	return Parse(data, o.ReadPass)
}

// ChangePasswordWithOptions 使用独立读写口令重新编码容器，并应用 PBE 与迭代参数。
// FriendlyName 为新名称；失败返回错误。
//
// ChangePasswordWithOptions rewrites a container using separate read/write passwords and PBE settings.
// FriendlyName supplies the new name; failures return errors.
func ChangePasswordWithOptions(data []byte, opts *Options) ([]byte, error) {
	b, err := ParseWithOptions(data, opts)
	if err != nil {
		return nil, err
	}
	defer asym.Close(b.PrivateKey)
	if b.Certificate != nil {
		defer b.Certificate.Close()
	}
	for _, c := range b.CACerts {
		defer c.Close()
	}
	return PackWithOptions(b.Certificate, b.PrivateKey, b.CACerts, opts)
}
