package asym

// Close 释放密钥持有的底层原生句柄（若有），幂等。
//
// k 为 nil、或 k 未持有句柄时返回 nil。本包所有算法密钥（SM2 / RSA / EC /
// Ed25519 / Ed448 / X25519 / X448）都由具体类型持有一个 EVP_PKEY 句柄，因此调用方
// 使用完毕后应显式释放，不要依赖 finalizer（Go 不保证执行，见 AGENTS.md §4.4）。
//
// 释放后再使用该密钥将返回错误（而非崩溃或静默返回零值）。
//
// ⚠️ 别名陷阱：`priv.Public()` 返回的公钥**共享同一个底层句柄**（不做 Dup），
// 因此对二者之一调用 Close 即释放该共享句柄，另一个也随之失效；随后对另一个再
// 调用 Close 只是幂等 no-op。若需要「销毁别名不影响原件」的语义，应经
// `internal/keyaccess` 取句柄后自行 `EVP_PKEY_dup`（下游 `ecdh` 正是这样做的），
// 而不要依赖 `Public()`。
//
// 注意：本函数**不复制**句柄——它释放的正是密钥对象自己持有的那一个。若下游
// （如 ecdh）已经按 internal/keyaccess 的契约 Dup 过一份，本调用不影响那份副本，
// 下游对象仍然可用（roadmap §10 风险项）。
//
// 之所以是包级函数而非接口方法：`Key` / `PrivateKey` / `PublicKey` 三个接口
// 刻意保持最小（仅算法标识 + 非导出句柄访问），把释放做成接口方法会让「可关闭」
// 成为公开契约并需要在 14 个具体类型上各补一份实现。包级函数在包内即可经
// `k.corePKey()` 取到句柄，且返回值只有 error、不暴露句柄，导出面最小。
//
// Close releases the native handle held by the key, if any; it is idempotent.
//
// It returns nil for a nil k or for a key holding no handle. Every algorithm key
// in this package (SM2 / RSA / EC / Ed25519 / Ed448 / X25519 / X448) owns an
// EVP_PKEY handle through its concrete type, so callers should release keys
// explicitly once done rather than relying on finalizers, which Go does not
// guarantee to run (see AGENTS.md §4.4).
//
// Using the key after Close returns an error rather than crashing or silently
// yielding zero values.
//
// ⚠️ Alias trap: the public key returned by priv.Public() **shares the same
// handle** (no Dup), so closing either one releases that shared handle and the
// other becomes unusable; a later Close on the other is merely an idempotent
// no-op. If you need "destroying the alias leaves the original intact", obtain
// the handle through internal/keyaccess and EVP_PKEY_dup it yourself — which is
// exactly what ecdh does — rather than relying on Public().
//
// Note that this function does **not** duplicate the handle: it releases the very
// handle owned by the key object. If a downstream consumer (such as ecdh) has
// already Dup'd it per the internal/keyaccess contract, that copy is unaffected
// and the downstream value stays usable (roadmap §10).
//
// It is a package-level function rather than an interface method because the
// Key / PrivateKey / PublicKey interfaces are deliberately minimal (algorithm
// identifier plus an unexported handle accessor); making Close an interface
// method would turn "closable" into a public contract and require an
// implementation on all 14 concrete types. A package-level function reaches the
// handle via k.corePKey() in-package and returns only an error, never a handle,
// keeping the exported surface minimal.
func Close(k Key) error {
	if k == nil {
		return nil
	}
	p := k.corePKey()
	if p == nil {
		return nil
	}
	return p.Close()
}
