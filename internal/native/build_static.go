//go:build static

package native

/*
#cgo CFLAGS: -I/opt/tongsuo/include -Wno-deprecated-declarations
#cgo linux LDFLAGS: -L/opt/tongsuo/lib64 -lcrypto -lssl -ldl -lpthread
*/
import "C"
