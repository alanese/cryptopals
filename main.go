package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"
)

func Challenge17Encrypt(key, iv []byte) []byte {
	options := []string{"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"}
	pText, _ := base64.StdEncoding.DecodeString(options[rand.Intn(len(options))])
	pText = PKCSPad(pText, 16)
	return EncryptAESCBC(pText, key, iv)
}

func Challenge17Decrypt(ctext, key, iv []byte) error {
	ptext := DecryptAESCBC(ctext, key, iv)
	_, err := StripPKCS7Padding(ptext, 16)
	return err
}

func Challenge17GetPrevByte(cText, knownBytes, key, iv []byte) byte {
	testLength := len(knownBytes) + 1
	head := cText[0 : len(cText)-len(knownBytes)-1]
	tail := cText[len(cText)-len(knownBytes)-1:]
	flipper := append([]byte{byte(0)}, knownBytes...)
	for i := 1; i < len(flipper); i++ {
		flipper[i] = flipper[i] ^ byte(testLength)
	}
	for i := 0; i < 256; i++ {
		flipper[0] = byte(i)
		testTail, _ := XorBufs(tail, flipper)
		testCtext := append(head, testTail...)
		err := Challenge17Decrypt(testCtext, key, iv)
		if err == nil {
			return byte(i) ^ byte(testLength)
		}

	}
	panic("Found no valid bytes")

}

func main() {
	rand.Seed(time.Now().Unix())
	key := GenerateRandomByteSlice(16)
	iv := GenerateRandomByteSlice(16)
	ctext := Challenge17Encrypt(key, iv)
	e := Challenge17Decrypt(ctext, key, iv)
	if e == nil {
		fmt.Println("Decrypt ok")
	}
	ctext = ctext[:32]
	knownBytes := []byte{}
	for i := 0; i < 16; i++ {
		nextByte := Challenge17GetPrevByte(ctext, knownBytes, key, iv)
		knownBytes = append([]byte{nextByte}, knownBytes...)
		fmt.Println(knownBytes)
	}

}
