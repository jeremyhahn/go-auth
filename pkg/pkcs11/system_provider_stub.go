//go:build !pkcs11 || !cgo

package pkcs11

func init() {
	systemSessionProvider = nil
}
