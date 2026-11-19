package asym

import (
	"errors"
	"fmt"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Options 配置 RSA 位数或 EC 曲线，零值分别使用 2048 位和 P-256。
//
// Options configures RSA bits or the EC curve. Zero values select 2048 bits and P-256.
type Options struct {
	// Bits 指定 RSA 位数。
	//
	// Bits specifies the RSA key size.
	Bits int

	// Curve 指定 EC 命名曲线。
	//
	// Curve specifies the named EC curve.
	Curve string
}

// GenerateKey 按算法名生成密钥。调用方负责 Close。
//
// GenerateKey generates a key by algorithm name. The caller must Close the key.
func GenerateKey(alg Algorithm, opts *Options) (PrivateKey, error) {
	alg = Algorithm(strings.ToUpper(string(alg)))
	var options Options
	if opts != nil {
		options = *opts
	}
	if (options.Bits != 0 && alg != AlgRSA) || (options.Curve != "" && alg != AlgEC) {
		return nil, fmt.Errorf("%w: generation options for %s", ErrInvalidKey, alg)
	}

	switch alg {
	case AlgRSA:
		if options.Bits == 0 {
			options.Bits = 2048
		}
		return GenerateRSA(options.Bits)
	case AlgEC:
		if options.Curve == "" {
			options.Curve = CurveP256
		}
		return GenerateEC(options.Curve)
	case AlgSM2:
		return GenerateSM2()
	case AlgEd25519:
		return GenerateEd25519()
	case AlgEd448:
		return GenerateEd448()
	case AlgX25519:
		return GenerateX25519()
	case AlgX448:
		return GenerateX448()
	}

	if !pqcVariant(alg) {
		return nil, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, alg)
	}
	key, err := core.GeneratePQCKey(string(alg))
	if errors.Is(err, core.ErrAlgorithmUnavailable) {
		return nil, fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	if err != nil {
		return nil, err
	}
	return &pqcPrivateKey{pqcKey{key: key, alg: alg}}, nil
}
