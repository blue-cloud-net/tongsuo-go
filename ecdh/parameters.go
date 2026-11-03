package ecdh

import (
	"fmt"
	"os"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// MarshalParametersPEM 导出命名或显式 EC 参数；X25519/X448 不使用 EC 参数文件。
// 失败返回错误。
//
// MarshalParametersPEM exports named or explicit EC parameters. X25519/X448 do not use
// EC parameter files. Failures return errors.
func MarshalParametersPEM(c *Curve, explicit bool) ([]byte, error) {
	if c == nil || c.kind.isOKP() {
		return nil, fmt.Errorf("ecdh: EC parameters require a Weierstrass curve")
	}
	return core.MarshalECParameters(c.ossl, explicit)
}

// LoadParametersPEM 读取命名或显式 EC 参数；不支持的曲线返回 ErrUnknownCurve。
//
// LoadParametersPEM reads named or explicit EC parameters; unsupported curves return ErrUnknownCurve.
func LoadParametersPEM(data []byte) (*Curve, error) {
	name, err := core.LoadECParameters(data)
	if err != nil {
		return nil, err
	}
	return CurveByName(name)
}

// LoadParametersFile 从本地文件读取 EC 参数；失败返回错误。
//
// LoadParametersFile reads EC parameters from a local file; failures return errors.
func LoadParametersFile(path string) (*Curve, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ecdh: read parameters: %w", err)
	}
	return LoadParametersPEM(data)
}

// GenerateKeyFromParameters 根据 PEM 参数生成密钥，调用方负责 asym.Close。
//
// GenerateKeyFromParameters generates a key from PEM parameters; callers must call asym.Close.
func GenerateKeyFromParameters(data []byte) (asym.PrivateKey, error) {
	c, err := LoadParametersPEM(data)
	if err != nil {
		return nil, err
	}
	return asym.GenerateEC(c.ossl)
}

// Check 校验 EC 曲线参数；X25519/X448 不支持此操作。
//
// Check validates EC curve parameters; this operation is unavailable for X25519/X448.
func (c *Curve) Check() error {
	data, err := MarshalParametersPEM(c, false)
	if err != nil {
		return err
	}
	_, err = LoadParametersPEM(data)
	return err
}
