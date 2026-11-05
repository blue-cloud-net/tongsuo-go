package ecdh_test

import (
	"bytes"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/ecdh"
)

// ExampleDeriveSM2DH 演示双方静态/临时密钥、显式角色和 ID；本例仅比较派生结果。
// 实际应用须认证静态公钥，每次重新生成临时密钥；调用方负责清零结果，另行完成密钥确认。
//
// ExampleDeriveSM2DH demonstrates static/ephemeral keys, explicit roles and IDs, comparing derived keys only.
// Authenticate static keys, generate fresh ephemeral keys and wipe results; complete key confirmation separately.
func ExampleDeriveSM2DH() {
	var keys []asym.PrivateKey
	defer func() {
		for _, key := range keys {
			asym.Close(key)
		}
	}()
	for i := 0; i < 4; i++ {
		key, err := asym.GenerateSM2()
		if err != nil {
			fmt.Println(err)
			return
		}
		keys = append(keys, key)
	}
	a, b, ra, rb := keys[0], keys[1], keys[2], keys[3]
	x, err := ecdh.DeriveSM2DH(&ecdh.SM2DHOptions{StaticKey: a, PeerStaticKey: b.Public(), EphemeralKey: ra, PeerEphemeralKey: rb.Public(), SelfID: []byte("Alice"), PeerID: []byte("Bob"), Role: ecdh.SM2DHInitiator, OutputLen: 32})
	if err != nil {
		fmt.Println(err)
		return
	}
	y, err := ecdh.DeriveSM2DH(&ecdh.SM2DHOptions{StaticKey: b, PeerStaticKey: a.Public(), EphemeralKey: rb, PeerEphemeralKey: ra.Public(), SelfID: []byte("Bob"), PeerID: []byte("Alice"), Role: ecdh.SM2DHResponder, OutputLen: 32})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(bytes.Equal(x, y))
	// Output: true
}
