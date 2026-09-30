package rand_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"

	tongsrand "github.com/blue-cloud-net/tongsuo-go/rand"
)

// ExampleRead 演示填充固定长度缓冲区。
func ExampleRead() {
	buf := make([]byte, 16)
	if _, err := tongsrand.Read(buf); err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(buf))
}

// ExampleBytes 演示一次性 Bytes 分配。
func ExampleBytes() {
	b, err := tongsrand.Bytes(16)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(b))
}

// ExampleReader 演示用 io.Copy 从随机流复制字节流。
// 同时展示同文件同时 import stdlib crypto/rand 与本包时的别名用法。
func ExampleReader() {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(tongsrand.Reader(), buf); err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(buf))

	// 校验：stdlib crypto/rand 与本包 RAND_bytes 都能填 32 字节
	std, err := rand.Read(make([]byte, 32))
	if err != nil || std != 32 {
		log.Fatalf("stdlib crypto/rand: n=%d err=%v", std, err)
	}
}
