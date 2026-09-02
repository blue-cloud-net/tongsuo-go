// Package xml 为 XML 序列化预留的命名空间。
//
// 当前包含 rsa 子包（.NET RSAKeyValue 格式 RSA 密钥序列化）。
//
// 未来 ECDSA / DSA / Ed25519 等 XML 序列化在此命名空间下扩展（如 xml/ecdsa）。
//
// 本包无独立类型，仅作为命名空间占位；调用方实际 import 的是其下的子包。
//
// Package xml reserves the XML serialization namespace.
//
// It currently hosts the rsa subpackage (.NET RSAKeyValue RSA-key
// serialization).
//
// And is the intended home for future XML serializers (xml/ecdsa,
// xml/dsa, xml/ed25519).
//
// The package itself defines no exported types; callers import the
// relevant subpackage instead.
package xml
