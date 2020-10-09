package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
)

//MysteryEncrypt sticks given plaintext on the front
//of some MYSTERY TEXT, pads it with PKCS#7,
//and encrypts with AES-ECB
func MysteryEncrypt(ptext []byte, key []byte) []byte {
	mysteryPtext := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	mysteryBytes, _ := base64.StdEncoding.DecodeString(mysteryPtext)
	newPtext := append(ptext, mysteryBytes...)
	newPtext = PKCSPad(newPtext, 16)
	return EncryptAESECB(newPtext, key)

}

//BreakMysteryEncrypt uncovers the MYSTERY TEXT from MysteryEncrypt
func BreakMysteryEncrypt(mysteryKey []byte) []byte {
	mysteryLength := len(MysteryEncrypt([]byte{}, mysteryKey))
	as := []byte("A")
	for {
		ctext := MysteryEncrypt(as, mysteryKey)
		if DetectAESECB(ctext) {
			break
		}
		as = append(as, byte('A'))
	}

	blockSize := len(as) / 2
	knownBytes := []byte{}
	for i := 0; i < blockSize-1; i++ {
		knownBytes = append(knownBytes, byte('A'))
	}
	for i := 0; i < mysteryLength; i++ {
		currentBlock := i / blockSize
		byteInBlock := i % blockSize

		targetHead := knownBytes[byteInBlock : blockSize-1]
		targetCText := MysteryEncrypt(targetHead, mysteryKey)

		for j := 0; j < 256; j++ {
			testHead := append(knownBytes[byteInBlock:], byte(j))
			testCText := MysteryEncrypt(testHead, mysteryKey)
			if bytes.Equal(targetCText[currentBlock*blockSize:(currentBlock+1)*blockSize],
				testCText[currentBlock*blockSize:(currentBlock+1)*blockSize]) {
				knownBytes = append(knownBytes, byte(j))
				break
			}
		}
	}
	return knownBytes[blockSize-1:]
}

//ParseKv parses something of the form k1=v1&k2=v2&k3=v3
//into a string-string map. Returns a non-nil error on a
//malformed input, or if regexp.MatchString returns one
func ParseKv(s string) (map[string]string, error) {
	validationRegex := "^([^&=]+=[^&=]+&)*[^&=]+=[^&=]+$"
	ok, err := regexp.MatchString(validationRegex, s)
	if !ok {
		return nil, errors.New("Malformed string")
	}
	if err != nil {
		return nil, err
	}

	pairs := strings.Split(s, "&")
	m := make(map[string]string)
	for _, p := range pairs {
		pair := strings.Split(p, "=")
		m[pair[0]] = pair[1]
	}
	return m, nil
}

//ProfileFor constructs a profile as per cryptopals challenge 13
func ProfileFor(email string) string {
	//strip encoding characters
	email = strings.ReplaceAll(email, "=", "")
	email = strings.ReplaceAll(email, "&", "")
	uid := fmt.Sprintf("%X", rand.Int())

	return "email=" + email + "&uid=" + uid + "&role=user"
}

//EncryptProfile encrypts the given profile string using AES-ECB
func EncryptProfile(profile string, key []byte) []byte {
	pText := PKCSPad([]byte(profile), 16)
	return EncryptAESECB(pText, key)
}

//DecryptParseProfile decrypts and parses a profile encrypted
//with AES-ECB
func DecryptParseProfile(ctext, key []byte) (map[string]string, error) {
	pText := string(DecryptAESECB(ctext, key))
	return ParseKv(pText)
}
