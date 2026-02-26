package main

import (
	"crypto/md5"
	"fmt"
	"net/http"
)

func login(user string, pass string) {
	// SOC2 Violation: Potential missing audit logging for login
	fmt.Printf("User %s is trying to login\n", user)
}

func main() {
	// SOC2 Violation: Insecure encryption (MD5)
	h := md5.New()
	h.Write([]byte("password123"))
	fmt.Printf("Hash: %x\n", h.Sum(nil))

	// SOC2 Violation: Unencrypted transmission (HTTP)
	resp, _ := http.Get("http://api.internal.health/records")
	fmt.Println(resp.Status)

	// SOC2 Violation: Hardcoded secret
	apiKey := "AKIA_SOC2_TEST_TOKEN_12345678"
	fmt.Println(apiKey)
}
