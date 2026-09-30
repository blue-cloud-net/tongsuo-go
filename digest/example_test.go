package digest_test

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/digest"
)

// ExampleSumSM3 演示一次性 SM3 摘要（GB/T 32905-2016 附录 A 的 "abc" 向量）。
//
// ExampleSumSM3 demonstrates a one-shot SM3 digest (the "abc" vector from
// Appendix A of GB/T 32905-2016).
func ExampleSumSM3() {
	sum := digest.SumSM3([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum[:]))
	// Output: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
}

// ExampleSumSHA256 演示一次性 SHA-256 摘要。
//
// ExampleSumSHA256 demonstrates a one-shot SHA-256 digest.
func ExampleSumSHA256() {
	sum := digest.SumSHA256([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum[:]))
	// Output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
}

// ExampleSumSHA224 演示一次性 SHA-224 摘要（本版新增算法）。
//
// ExampleSumSHA224 demonstrates a one-shot SHA-224 digest (an algorithm
// added by this version).
func ExampleSumSHA224() {
	sum := digest.SumSHA224([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum[:]))
	// Output: 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7
}

// ExampleSumSHA384 演示一次性 SHA-384 摘要（本版新增算法）。
//
// ExampleSumSHA384 demonstrates a one-shot SHA-384 digest (an algorithm
// added by this version).
func ExampleSumSHA384() {
	sum := digest.SumSHA384([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum[:]))
	// Output: cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
}

// ExampleNew 演示流式 SM3：多次 Write 累加后再取摘要。
//
// ExampleNew demonstrates streaming SM3: data is accumulated over several
// Write calls before reading the digest.
func ExampleNew() {
	h := digest.NewSM3()
	h.Write([]byte("ab"))
	h.Write([]byte("c"))
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
	// Output: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
}

// ExampleNew_reset 演示 Reset 后复用同一 hash.Hash 实例。
//
// ExampleNew_reset demonstrates reusing one hash.Hash instance after Reset.
func ExampleNew_reset() {
	h := digest.NewSM3()
	h.Write([]byte("abc"))
	first := h.Sum(nil)

	h.Reset()
	h.Write([]byte("abc"))
	second := h.Sum(nil)

	fmt.Println(hex.EncodeToString(first) == hex.EncodeToString(second))
	// Output: true
}

// ExampleNew_byName 演示按算法名获取流式哈希。
//
// ExampleNew_byName demonstrates obtaining a streaming hash by algorithm
// name.
func ExampleNew_byName() {
	h, err := digest.New("SHA256")
	if err != nil {
		log.Fatal(err)
	}
	h.Write([]byte("abc"))
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
	// Output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
}

// ExampleSum_byName 演示按算法名一次性计算摘要。
//
// ExampleSum_byName demonstrates a one-shot digest by algorithm name.
func ExampleSum_byName() {
	sum, err := digest.Sum("SHA384", []byte("abc"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(sum))
	// Output: cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
}

// ExampleSumReader 演示从 io.Reader 流式计算摘要。
//
// ExampleSumReader demonstrates streaming a digest from an io.Reader.
func ExampleSumReader() {
	sum, err := digest.SumReader("SM3", strings.NewReader("abc"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(sum))
	// Output: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
}

// ExampleNames 演示查询本版支持的算法名列表。
//
// ExampleNames demonstrates listing the algorithm names supported by this
// version.
func ExampleNames() {
	fmt.Println(strings.Join(digest.Names(), ","))
	// Output: SM3,MD5,SHA1,SHA224,SHA256,SHA384,SHA512
}

// ExampleSize 演示按名查询摘要长度，并演示未知算法名的错误判定。
//
// ExampleSize demonstrates looking up a digest length by name and also how
// to detect an unknown algorithm name.
func ExampleSize() {
	n, err := digest.Size("SHA384")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(n)

	if _, err := digest.Size("NOPE"); err != nil {
		fmt.Println("unknown algorithm rejected")
	}
	// Output: 48
	// unknown algorithm rejected
}
