package meta_test

import (
	"fmt"
	"log"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// ExampleVersion 演示读取铜锁完整版本 banner。
//
// ExampleVersion demonstrates reading the full Tongsuo version banner.
// Output is omitted on purpose: the banner content varies with the
// Tongsuo/OpenSSL build linked into the binary, so a hard-coded
// // Output: line would break `go test` across versions.
func ExampleVersion() {
	fmt.Println(meta.Version())
}

// ExampleVersionString 演示解析纯版本号字符串。
//
// ExampleVersionString demonstrates reading the bare version string.
// Output is omitted for the same reason as ExampleVersion.
func ExampleVersionString() {
	fmt.Println(meta.VersionString())
}

// ExampleReadBuildInfo 演示读取构建信息快照。
//
// ExampleReadBuildInfo demonstrates reading a build-info snapshot.
// Output is omitted for the same reason as ExampleVersion.
func ExampleReadBuildInfo() {
	bi := meta.ReadBuildInfo()
	if bi == nil {
		log.Fatal("ReadBuildInfo returned nil")
	}
	fmt.Printf("OPENSSLDIR=%q platform=%q\n", bi.OpenSSLDir, bi.Platform)
}

// ExampleErrorString 演示将原生错误码转为文本。
// 错误码 0x0906D06C 在 Tongsuo 8.x 是 lib=18, reason=184428（固定常量）。
//
// ExampleErrorString demonstrates converting a native error code to text.
// Code 0x0906D06C is lib=18, reason=184428 on Tongsuo 8.x and is fixed.
func ExampleErrorString() {
	fmt.Println(meta.ErrorString(0x0906D06C))
	// Output: error:0906D06C:lib(18)::reason(184428)
}

// ExampleParseErrorCode_hex 演示解析十六进制错误码。
//
// ExampleParseErrorCode_hex demonstrates parsing a hex error code.
func ExampleParseErrorCode_hex() {
	code, err := meta.ParseErrorCode("0x0906D06C")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("0x%x\n", code)
	// Output: 0x906d06c
}

// ExampleParseErrorCode_dec 演示解析十进制错误码。
//
// ExampleParseErrorCode_dec demonstrates parsing a decimal error code.
func ExampleParseErrorCode_dec() {
	code, err := meta.ParseErrorCode("184428")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("0x%x\n", code)
	// Output: 0x2d06c
}

// ExampleParseErrorCode_unprefixed 演示解析无前缀的十六进制错误码（兜底）。
//
// ExampleParseErrorCode_unprefixed demonstrates parsing unprefixed hex
// (the fallback path).
func ExampleParseErrorCode_unprefixed() {
	code, err := meta.ParseErrorCode("0906D06C")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("0x%x\n", code)
	// Output: 0x906d06c
}
