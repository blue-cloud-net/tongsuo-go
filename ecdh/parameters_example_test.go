package ecdh_test

import (
	"fmt"
	"github.com/blue-cloud-net/tongsuo-go/ecdh"
)

// ExampleMarshalParametersPEM 展示命名曲线参数往返。
//
// ExampleMarshalParametersPEM demonstrates a named-curve parameter round trip.
func ExampleMarshalParametersPEM() {
	data, err := ecdh.MarshalParametersPEM(ecdh.P256(), false)
	if err != nil {
		fmt.Println(err)
		return
	}
	curve, err := ecdh.LoadParametersPEM(data)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(curve.Name())
	// Output: P-256
}
