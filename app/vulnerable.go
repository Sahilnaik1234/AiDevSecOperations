package main

import (
	"crypto/md5"
	"fmt"
	"net/http"
)

func main() {
	// SOC2 Violation: Insecure encryption (MD5)
	h := md5.New()
	h.Write([]byte("password123"))
	fmt.Printf("Hash: %x\n", h.Sum(nil))
}
