package keystore_test

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/keystore"
	"github.com/blue-cloud-net/tongsuo-go/sym"
)

// ExampleNewHandle 演示从对称密钥构造带元数据的密钥条目。
func ExampleNewHandle() {
	key, err := sym.NewSM4Key([]byte("0123456789abcdef"))
	if err != nil {
		log.Fatal(err)
	}
	h, err := keystore.NewHandle("sm4-1", key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(h.ID, h.Algorithm, h.Version)
	// Output: sm4-1 SM4 1
}

// ExampleMemoryStore 演示内存存储的存入、轮转与历史查询。
func ExampleMemoryStore() {
	s := keystore.NewMemoryStore()

	first, err := sym.NewSM4Key([]byte("0123456789abcdef"))
	if err != nil {
		log.Fatal(err)
	}
	h, err := keystore.NewHandle("sm4-1", first)
	if err != nil {
		log.Fatal(err)
	}
	if err := s.Put(h); err != nil {
		log.Fatal(err)
	}

	second, err := sym.NewSM4Key([]byte("fedcba9876543210"))
	if err != nil {
		log.Fatal(err)
	}
	rotated, err := s.Rotate("sm4-1", second)
	if err != nil {
		log.Fatal(err)
	}
	hist, err := s.History("sm4-1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(rotated.Version, hist[0].Version)
	// Output: 2 1
}

// ExampleUnmarshalHandle 演示以 PEM 内嵌形式往返 JSON。
//
// 本包不 import asym / sym，因此解码器由调用方注入：按 PEM 块类型分派。
func ExampleUnmarshalHandle() {
	priv, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		log.Fatal(err)
	}
	h, err := keystore.NewHandle("ec-1", priv)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := h.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	data, err := json.Marshal(h)
	if err != nil {
		log.Fatal(err)
	}

	back, err := keystore.UnmarshalHandle(data, func(pemBytes []byte) (any, error) {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("no PEM block found")
		}
		if strings.HasSuffix(block.Type, "PUBLIC KEY") {
			return asym.LoadPublicKeyPEM(pemBytes)
		}
		return asym.LoadPrivateKeyPEM(pemBytes)
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := back.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	fmt.Println(back.ID, back.Algorithm, back.Key != nil)
	// Output: ec-1 EC true
}
