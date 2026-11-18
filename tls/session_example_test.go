package tls

import "fmt"

// ExampleTicketKeyManager_SetKeys 演示首项签发、旧密钥过渡解密的显式轮换。
//
// ExampleTicketKeyManager_SetKeys demonstrates explicit rotation with the first key issuing and the old key decrypting during transition.
func ExampleTicketKeyManager_SetKeys() {
	manager, err := NewTicketKeyManager()
	if err != nil {
		fmt.Println(err)
		return
	}
	old, err := GenerateTicketKey()
	if err != nil {
		fmt.Println(err)
		return
	}
	current, err := GenerateTicketKey()
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := manager.SetKeys([]TicketKey{current, old}); err != nil {
		fmt.Println(err)
		return
	}
	// Share manager between server configurations using the same SessionPolicyID.
	config := &Config{TicketKeys: manager, SessionPolicyID: "service-policy-v1"}
	fmt.Println(config.SessionPolicyID)
	// Output: service-policy-v1
}
