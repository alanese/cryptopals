package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"
)

//Challenge17Encrypt randomly chooses one of 10 Base64-encoded
//strings, decodes it, pads it, and encrypts it with AES-CBC
//using the given key and IV
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

//Challenge17Decrypt decrypts the given AES-CBC ciphertext
//with the given key and IV and returns a nil error if
//the plaintext is properly PKCS#7-padded, non-nil otherwise
func Challenge17Decrypt(ctext, key, iv []byte) error {
	ptext := DecryptAESCBC(ctext, key, iv)
	_, err := StripPKCS7Padding(ptext, 16)
	return err
}

//Challenge17GetPrevByte , given a ciphertext and a known suffix
//of the plaintext, finds the plaintext byte preceding the known
//suffix using a padding oracle attack.
func Challenge17GetPrevByte(cText, knownBytes, key, iv []byte) byte {
	testLength := len(knownBytes) + 1
	head := cText[0 : len(cText)-testLength-16]
	mid := cText[len(cText)-testLength-16 : len(cText)-16]
	tail := cText[len(cText)-16:]
	flipper := append([]byte{byte(0)}, knownBytes...)
	for i := 1; i < len(flipper); i++ {
		flipper[i] = flipper[i] ^ byte(testLength)
	}
	testCtext := bytes.NewBuffer([]byte{})
	for i := 0; i < 256; i++ {
		flipper[0] = byte(i)
		testMid, _ := XorBufs(mid, flipper)
		_, _ = testCtext.Write(head)
		_, _ = testCtext.Write(testMid)
		_, _ = testCtext.Write(tail)
		err := Challenge17Decrypt(testCtext.Bytes(), key, iv)
		if err == nil {
			if testLength > 1 {
				return byte(i) ^ byte(testLength)
			}
			testCtext.Reset()
			_, _ = testCtext.Write(head[:len(head)-1])
			_ = testCtext.WriteByte(head[len(head)-1] ^ byte(1))
			_, _ = testCtext.Write(testMid)
			_, _ = testCtext.Write(tail)
			err := Challenge17Decrypt(testCtext.Bytes(), key, iv)
			if err == nil {
				return byte(i) ^ byte(testLength)

			}
		}
		testCtext.Reset()

	}
	panic("Found no valid bytes")
}

//Challenge17GetLastBlock finds the last plaintext block
//of the given ciphertext using a CBC padding oracle attack
func Challenge17GetLastBlock(cText, key, iv []byte) []byte {
	knownBytes := []byte{}
	for i := 0; i < 16; i++ {
		nextByte := Challenge17GetPrevByte(cText, knownBytes, key, iv)
		knownBytes = append([]byte{nextByte}, knownBytes...)
	}
	return knownBytes
}

//Challenge18Decrypt decrypts the text from challenge 18.
func Challenge18Decrypt() {
	key := []byte("YELLOW SUBMARINE")
	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	cText, _ := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	keystream := GenerateCTRKeystream(6, key, nonce, LittleEndianCounter)
	keystream = keystream[:len(cText)]
	pText, _ := XorBufs(keystream, cText)
	fmt.Println(string(pText))

}

//Challenge20 breaks fixed-nonce CTR statistically as per challenge 20
func Challenge20(sourceFname, sampleFname string) {
	lines, _ := LinesFromFile(sourceFname)
	decodedLines := make([][]byte, len(lines)-1)
	minLength := 99999999
	for i, v := range lines[:len(lines)-1] {
		line, _ := base64.StdEncoding.DecodeString(string(v))
		decodedLines[i] = line
		if len(line) < minLength {
			minLength = len(line)
		}
	}
	truncatedLines := []byte{}
	for _, v := range decodedLines {
		truncatedLines = append(truncatedLines, v[:minLength]...)
	}

	targetFreq, _ := FileFreqCount(sampleFname)

	pText := BreakKnownLenRepeatedXor(truncatedLines, minLength, targetFreq)
	fmt.Println(string(pText))
}
