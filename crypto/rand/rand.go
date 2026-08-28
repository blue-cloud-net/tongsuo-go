// Package rand 基于铜锁原生实现提供加密安全随机数生成。
//
// 提供与 io.Reader 语义一致的 Read 以及一次性便捷函数 Bytes。
//
// 注意：包路径与 Go 标准库 crypto/rand 同名，调用方引用本包时**必须使用完整路径**
// 或起一个明确别名以避免被 stdlib 抢占：
//
//	import tongsrand "github.com/blue-cloud-net/tongsuo-go/crypto/rand"
//	// 或
//	import "github.com/blue-cloud-net/tongsuo-go/crypto/rand"
//
// 与 stdlib crypto/rand 的区别：本包底层走 Tongsuo RAND_bytes（OpenSSL CSPRNG），
// stdlib crypto/rand 在 Linux 上走 getrandom(2)。两者均属密码学安全随机数。
package rand

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// Read 使用铜锁 RAND_bytes 将加密安全随机字节填充到 b。
// 返回实际写入的字节数（等于 len(b)）；底层失败时返回错误。
func Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if !native.RAND_bytes(b) {
		return 0, core.NewOpError("rand: RAND_bytes", native.PopError())
	}
	return len(b), nil
}

// Bytes 返回 n 个加密安全随机字节。
func Bytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("rand: negative length %d", n)
	}
	b := make([]byte, n)
	if _, err := Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
