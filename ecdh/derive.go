package ecdh

import (
	"errors"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/keyaccess"
)

const (
	maxSM2DHIDSize     = (1<<16 - 1) / 8
	maxSM2DHOutputSize = 1<<31 - 1
)

// ErrUnsupported 表示当前原生构建不支持请求的协商操作。
//
// ErrUnsupported means the requested agreement operation is unavailable in the native build.
var ErrUnsupported = errors.New("ecdh: unsupported operation")

// DeriveSharedSecret 从 asym 密钥直接派生 EC/X25519/X448 原始共享秘密。
// 使用独立副本，不关闭源密钥；错误曲线、关闭密钥和低阶点均返回错误。
// SM2DH 需要额外参数，应使用 DeriveSM2DH。返回值须经 KDF 使用并由调用方清零。
//
// DeriveSharedSecret derives an EC/X25519/X448 raw shared secret directly from asym keys.
// It uses independent copies; mismatched curves, closed keys and low-order points return errors.
// SM2DH requires DeriveSM2DH. Apply a KDF before use and wipe the result after use.
func DeriveSharedSecret(priv asym.PrivateKey, pub asym.PublicKey) ([]byte, error) {
	a, err := LoadPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	defer a.Close()
	b, err := LoadPublicKey(pub)
	if err != nil {
		return nil, err
	}
	defer b.Close()
	return SharedSecret(a, b)
}

// SM2DHRole 表示 SM2DH 协商角色；零值无效，双方必须使用互补角色。
//
// SM2DHRole identifies an SM2DH role; zero is invalid and peers must use complementary roles.
type SM2DHRole uint8

const (
	// SM2DHInitiator 是协商发起方。
	//
	// SM2DHInitiator is the initiating peer.
	SM2DHInitiator SM2DHRole = iota + 1
	// SM2DHResponder 是协商响应方。
	//
	// SM2DHResponder is the responding peer.
	SM2DHResponder
)

// SM2DHOptions 显式指定静态/临时密钥、ID、角色及派生长度，摘要固定 SM3。
// ID 必须显式提供且为 1..8191 字节；OutputLen 为 1..2147483647 字节。
// 临时私钥必须为每次协商新生成；调用期间不得关闭任何输入密钥。
//
// SM2DHOptions supplies static/ephemeral keys, IDs, role and output length, using SM3.
// IDs must be explicitly supplied with 1..8191 bytes; OutputLen is 1..2147483647 bytes.
// Generate a fresh ephemeral private key for every exchange; do not close inputs during the call.
type SM2DHOptions struct {
	// StaticKey 是本方静态私钥。
	//
	// StaticKey is the local static private key.
	StaticKey asym.PrivateKey
	// PeerStaticKey 是对端静态公钥，调用方负责认证其身份。
	//
	// PeerStaticKey is the peer static public key, whose identity the caller must authenticate.
	PeerStaticKey asym.PublicKey
	// EphemeralKey 是本次协商的新临时私钥。
	//
	// EphemeralKey is the fresh local ephemeral private key.
	EphemeralKey asym.PrivateKey
	// PeerEphemeralKey 是对端本次协商的临时公钥。
	//
	// PeerEphemeralKey is the peer ephemeral public key for this exchange.
	PeerEphemeralKey asym.PublicKey
	// SelfID 是本方身份标识符。
	//
	// SelfID is the local identity identifier.
	SelfID []byte
	// PeerID 是对端身份标识符。
	//
	// PeerID is the peer identity identifier.
	PeerID []byte
	// Role 指定发起方或响应方，零值无效。
	//
	// Role selects initiator or responder; zero is invalid.
	Role SM2DHRole
	// OutputLen 指定派生密钥字节数。
	//
	// OutputLen specifies the derived key length in bytes.
	OutputLen int
}

// DeriveSM2DH 使用铜锁 SM2DH 与 SM3 派生密钥，内部复制并释放四个句柄。
// 不生成或验证密钥确认消息；派生成功不代表对端认证或密钥确认完成。
// 参数非法返回错误，原生不支持返回 ErrUnsupported；调用方负责清零结果。
//
// DeriveSM2DH derives an SM2DH key through Tongsuo and SM3, copying and releasing four handles.
// It does not generate or verify confirmation messages; success does not authenticate the peer or confirm the key.
// Invalid arguments return errors, unavailable support returns ErrUnsupported; callers must wipe the result.
func DeriveSM2DH(opts *SM2DHOptions) ([]byte, error) {
	if opts == nil || (opts.Role != SM2DHInitiator && opts.Role != SM2DHResponder) ||
		len(opts.SelfID) == 0 || len(opts.SelfID) > maxSM2DHIDSize || len(opts.PeerID) == 0 || len(opts.PeerID) > maxSM2DHIDSize ||
		opts.OutputLen <= 0 || uint64(opts.OutputLen) > uint64(maxSM2DHOutputSize) {
		return nil, fmt.Errorf("ecdh: invalid SM2DH options")
	}
	keys := make([]*core.PKey, 0, 4)
	defer func() {
		for _, key := range keys {
			key.Close()
		}
	}()
	for _, key := range []asym.Key{opts.EphemeralKey, opts.PeerEphemeralKey, opts.StaticKey, opts.PeerStaticKey} {
		if key == nil || key.Algorithm() != asym.AlgSM2 {
			return nil, fmt.Errorf("ecdh: SM2DH requires SM2 keys: %w", ErrUnsupportedKey)
		}
		k, ok := keyaccess.PKey(key)
		if !ok || k == nil {
			return nil, fmt.Errorf("ecdh: invalid SM2DH key: %w", ErrUnsupportedKey)
		}
		dup, err := k.Dup()
		if err != nil {
			return nil, fmt.Errorf("ecdh: SM2DH key: %w", err)
		}
		keys = append(keys, dup)
	}
	out, err := core.DeriveSM2DH(keys[0], keys[1], keys[2], keys[3], opts.Role == SM2DHInitiator,
		opts.SelfID, opts.PeerID, opts.OutputLen)
	if errors.Is(err, core.ErrAlgorithmUnavailable) {
		return nil, fmt.Errorf("ecdh: SM2DH: %w: %w", ErrUnsupported, err)
	}
	return out, err
}
