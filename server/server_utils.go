package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"time"
)

//InsecureCompare determines whether two byte slices
//contain the same elements with early exit, with an
//artificially-emphasized timing leak
func InsecureCompare(b1, b2 []byte) bool {
	if len(b1) != len(b2) {
		return false
	}
	for i := range b1 {
		if b1[i] != b2[i] {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}

	return true
}

//PadLeft pads a byte slice by adding copies of a given
//byte to the left; returns the original slice if longer
//than the specified length
func PadLeft(orig []byte, pad byte, length int) []byte {
	if len(orig) >= length {
		return orig
	}
	b := bytes.NewBuffer([]byte{})
	toAdd := length - len(orig)
	for i := 0; i < toAdd; i++ {
		b.WriteByte(pad)
	}
	b.Write(orig)
	return b.Bytes()
}

//XorBufs computes the bitwise xor of two byte slices
//Returns a non-nil error if the two slices are of different lengths
func XorBufs(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, errors.New("Buffers of unequal length")
	}
	tmp := make([]byte, len(b1))
	for i := range b1 {
		tmp[i] = b1[i] ^ b2[i]
	}
	return tmp, nil
}

//HMACSHA1 computes an SHA-1 based HMAC with the given
//message and secret
func HMACSHA1(secret, msg []byte) []byte {
	var k []byte
	if len(secret) > 64 {
		t := sha1.Sum(secret)
		k = t[:]
	} else {
		k = make([]byte, 64)
		for i, v := range secret {
			k[i] = v
		}
	}
	opad := make([]byte, 64)
	ipad := make([]byte, 64)
	for i := range opad {
		opad[i] = 0x5C
		ipad[i] = 0x36
	}

	iKey, _ := XorBufs(k, ipad)
	oKey, _ := XorBufs(k, opad)

	m := sha1.Sum(append(iKey, msg...))
	m = sha1.Sum(append(oKey, m[:]...))
	return m[:]
}

//C31VerifyHMAC verifies that the secret-prefix HMAC of
//the file query parameter equals the signature parameter
func C31VerifyHMAC(rw http.ResponseWriter, rq *http.Request) {
	secret := []byte("THIS IS A SECRET DON'T TELL ANYONE")
	file := []byte(rq.URL.Query().Get("file"))
	hmac, _ := hex.DecodeString(rq.URL.Query().Get("signature"))
	hmac = PadLeft(hmac, 0, 20)
	fileHmac := HMACSHA1(secret, file)
	if InsecureCompare(fileHmac, hmac) {
		rw.Write([]byte("OK"))
	} else {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Invalid hash"))
	}
}

//C31StartServer starts an HMAC-verifying server per challenge 31
//Must either be run in a separate program from the client, or as
//a goroutine (which is much less consistent)
func C31StartServer() {
	http.HandleFunc("/", C31VerifyHMAC)
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}
