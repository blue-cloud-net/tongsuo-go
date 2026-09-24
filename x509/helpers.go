package x509

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/keyaccess"
)

// corePublicKey 经 internal/keyaccess 取出 asym 公钥的底层句柄。
//
// 句柄仍由传入的 asym 公钥对象持有，本函数只是**借用**：调用方在调用期间需保证
// 该对象存活。之所以不 Dup：这些助手只用于「把句柄交给 `X509_set_pubkey` /
// `X509_sign` / `X509_REQ_sign` 立即使用」的瞬时场景（前者内部会 up-ref，后者在
// 调用内用完即弃）；keyaccess 契约要求的 Dup 针对的是「取出来继续持有」。
//
// corePublicKey extracts the underlying handle of an asym public key through
// internal/keyaccess.
//
// The handle is still owned by the passed key: this function merely borrows it,
// so the caller must keep that key alive for the duration of the call. No Dup is
// performed because these helpers only feed instantaneous uses such as
// X509_set_pubkey / X509_sign / X509_REQ_sign — the former up-refs internally and
// the latter consumes the key within the call. The Dup required by the keyaccess
// contract applies to handles extracted for later use.
func corePublicKey(pub asym.PublicKey) (*core.PKey, error) {
	if pub == nil {
		return nil, fmt.Errorf("x509: nil public key")
	}
	k, ok := keyaccess.PKey(pub)
	if !ok || k == nil {
		return nil, fmt.Errorf("x509: unsupported public key type %T", pub)
	}
	return k, nil
}

// corePrivateKey 经 internal/keyaccess 取出 asym 私钥的底层句柄（只借用，同
// corePublicKey 的说明）。
//
// corePrivateKey extracts the underlying handle of an asym private key through
// internal/keyaccess (borrowed only, see corePublicKey).
func corePrivateKey(priv asym.PrivateKey) (*core.PKey, error) {
	if priv == nil {
		return nil, fmt.Errorf("x509: nil private key")
	}
	k, ok := keyaccess.PKey(priv)
	if !ok || k == nil {
		return nil, fmt.Errorf("x509: unsupported private key type %T", priv)
	}
	return k, nil
}

// wrapCorePublicKey 把底层公钥句柄换成 asym.PublicKey。
//
// 实现方式是 **PEM 往返**：`MarshalPublicKeyPEM` → `asym.LoadPublicKeyPEM`。
// 之所以不直接构造：`asym` 的包装函数（`wrapPublicKey`）非导出，而给 `asym`
// 新加一个收 `*core.PKey` 的公开入口会让公开签名再次出现 internal/ 类型
// （正是 roadmap §5 E1 要消除的）。PEM 往返零新增 API、零泄漏，代价是每次调用
// 一次编解码——本函数只用在读访问器（Certificate.PublicKey /
// CertificateRequest.PublicKey）上，不在热路径。
//
// 返回的对象**拥有**自己的句柄，调用方需用 asym.Close 释放。
//
// wrapCorePublicKey turns an underlying public-key handle into an asym.PublicKey.
//
// It performs a PEM round trip (MarshalPublicKeyPEM → asym.LoadPublicKeyPEM).
// Constructing the value directly is not possible: asym's wrapper is unexported,
// and adding a public asym entry point taking a *core.PKey would put an internal/
// type back into a public signature — exactly what roadmap §5 E1 eliminates. The
// round trip adds no API and leaks nothing, at the cost of one encode/decode per
// call; this helper only serves read accessors (Certificate.PublicKey,
// CertificateRequest.PublicKey) and is not on a hot path.
//
// The returned value **owns** its handle; release it with asym.Close.
func wrapCorePublicKey(k *core.PKey) (asym.PublicKey, error) {
	if k == nil {
		return nil, fmt.Errorf("x509: nil public key handle")
	}
	pemBytes, err := k.MarshalPublicKeyPEM()
	if err != nil {
		return nil, err
	}
	return asym.LoadPublicKeyPEM(pemBytes)
}

// convertEntries 将 core.NameEntry 切片转为 API 层 NameEntry 切片。
func convertEntries(es []core.NameEntry) []NameEntry {
	out := make([]NameEntry, 0, len(es))
	for _, e := range es {
		out = append(out, NameEntry{Nid: e.Nid, Field: e.Field, Value: e.Value})
	}
	return out
}

// convertExtensions 将 core.Extension 切片转为 API 层 Extension 切片。
func convertExtensions(es []core.Extension) []Extension {
	out := make([]Extension, 0, len(es))
	for _, e := range es {
		out = append(out, Extension{
			Nid:      e.Nid,
			Field:    e.Field,
			OID:      e.OID,
			Critical: e.Critical,
			Value:    e.Value,
			Data:     e.Data,
		})
	}
	return out
}
