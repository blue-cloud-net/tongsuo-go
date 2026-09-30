// Package keystore 提供算法无关的密钥元数据管理、内存存储与轮转。
//
// 本包只处理「密钥条目的组织方式」，不处理算法本身：
//
//   - 非对称密钥抽象与算法实现见 asym 包；
//   - 对称密钥抽象与算法实现见 sym 包；
//   - 密钥派生见 kdf 包。
//
// 因此 Handle.Key 的类型是 any（不 import asym / sym，避免反向依赖），
// 算法名由 Handle.Algorithm（string）承载。少数需要与密钥对象交互的地方
// （取底层句柄、序列化 PEM）通过包内窄接口完成，不引入包依赖。
//
// 所有权约定：Store 不接管密钥所有权。被覆盖、轮转归档或删除的 Handle
// 均不会被自动释放，调用方须对不再使用的 Handle 调用 Close。
//
// Package keystore provides algorithm-agnostic key metadata management,
// an in-memory store and key rotation.
//
// This package deals only with how key entries are organised, never with
// the algorithms themselves:
//
//   - asymmetric abstractions live in asym;
//   - symmetric abstractions live in sym;
//   - key derivation lives in kdf.
//
// Handle.Key is therefore typed any (the package does not import asym or
// sym, avoiding reverse dependencies) while the algorithm name is carried
// by Handle.Algorithm (a string). The few places that must interact with a
// key object (reclaiming its native handle, serialising it to PEM) go
// through narrow package-local interfaces rather than package imports.
//
// Ownership: a Store never takes ownership of keys. Handles that are
// overwritten, archived by rotation or deleted are never closed
// automatically — callers must Close handles they no longer use.
package keystore
