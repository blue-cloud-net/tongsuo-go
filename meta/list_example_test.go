package meta_test

import (
	"fmt"
	"log"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// ExampleDigests 演示枚举当前 provider 提供的摘要算法。
//
// ExampleDigests demonstrates enumerating the message-digest algorithms
// provided by the current providers.
// Output is omitted on purpose: the list depends on the linked Tongsuo
// build, so a hard-coded // Output: line would break `go test` across
// versions.
func ExampleDigests() {
	fmt.Println(meta.Digests())
}

// ExampleCiphers 演示枚举当前 provider 提供的对称加密算法。
//
// ExampleCiphers demonstrates enumerating the symmetric ciphers provided
// by the current providers.
// Output is omitted on the same reason as ExampleDigests.
func ExampleCiphers() {
	fmt.Println(meta.Ciphers())
}

// ExampleMACs 演示枚举当前 provider 提供的 MAC 算法。
//
// ExampleMACs demonstrates enumerating the MAC algorithms provided by the
// current providers.
// Output is omitted on the same reason as ExampleDigests.
func ExampleMACs() {
	fmt.Println(meta.MACs())
}

// ExampleKDFs 演示枚举当前 provider 提供的 KDF 算法。
//
// ExampleKDFs demonstrates enumerating the KDF algorithms provided by the
// current providers.
// Output is omitted on the same reason as ExampleDigests.
func ExampleKDFs() {
	fmt.Println(meta.KDFs())
}

// ExampleTLSGroups 演示枚举当前构建实现的 TLS 组。
//
// ExampleTLSGroups demonstrates enumerating the TLS groups implemented by
// the current build.
// Output is omitted on the same reason as ExampleDigests.
func ExampleTLSGroups() {
	fmt.Println(meta.TLSGroups())
}

// ExampleProviders 演示列出活跃的 provider。
//
// ExampleProviders demonstrates listing the active providers.
// Output is omitted on the same reason as ExampleDigests.
func ExampleProviders() {
	for _, p := range meta.Providers() {
		fmt.Printf("%s %s %s\n", p.Name, p.Version, p.Status)
	}
}

// ExampleSeedingSource 演示查询随机数种子来源。
//
// ExampleSeedingSource demonstrates querying the random seed source.
// Output is omitted on the same reason as ExampleDigests.
func ExampleSeedingSource() {
	fmt.Println(meta.SeedingSource())
}

// ExampleEncode 演示按编码转换字节的文本形态。
//
// ExampleEncode demonstrates converting bytes to their textual form
// according to an encoding.
func ExampleEncode() {
	data := []byte("hello")
	hexOut, err := meta.Encode(data, meta.EncodingHex)
	if err != nil {
		log.Fatal(err)
	}
	b64Out, err := meta.Encode(data, meta.EncodingBase64)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s %s\n", hexOut, b64Out)
	// Output: 68656c6c6f aGVsbG8=
}

// ExampleDecode 演示把文本解码回字节。
//
// ExampleDecode demonstrates decoding text back into bytes.
func ExampleDecode() {
	got, err := meta.Decode([]byte("68656c6c6f"), meta.EncodingHex)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(got))
	// Output: hello
}

// ExampleDump 演示生成 hexdump 视图。
//
// ExampleDump demonstrates producing a hexdump view.
func ExampleDump() {
	fmt.Println(meta.Dump([]byte("hi")))
	// Output: 00000000  68 69                                             |hi|
}

// ExampleNewBytesSource 演示从内存字节构造输入源并读取。
//
// ExampleNewBytesSource demonstrates building an input source from
// in-memory bytes and reading it.
func ExampleNewBytesSource() {
	src := meta.NewBytesSource([]byte("tongsuo-go"))
	data, err := src.ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))
	// Output: tongsuo-go
}

// ExampleNewBytesSink 演示写入内存输出汇并取回编码后的内容。
//
// ExampleNewBytesSink demonstrates writing to an in-memory output sink
// and retrieving the encoded content.
func ExampleNewBytesSink() {
	sink := meta.NewBytesSink()
	if err := sink.SetEncoding(meta.EncodingHex); err != nil {
		log.Fatal(err)
	}
	if _, err := sink.Write([]byte("hi")); err != nil {
		log.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(sink.Bytes()))
	// Output: 6869
}

// ExampleNewPassphrase 演示按来源说明构造口令，并确认描述不含口令内容。
//
// ExampleNewPassphrase demonstrates building a passphrase from a source
// specification and confirming that its description leaks nothing.
func ExampleNewPassphrase() {
	p, err := meta.NewPassphrase("pass:example-secret")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(p.String())
	fmt.Println(strings.Contains(p.String(), "example-secret"))
	// Output:
	// pass:***
	// false
}

// ExampleParseFormat 演示解析 PEM / DER 格式名。
//
// ExampleParseFormat demonstrates parsing a PEM / DER format name.
func ExampleParseFormat() {
	f, err := meta.ParseFormat("pem")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(f)
	// Output: PEM
}
