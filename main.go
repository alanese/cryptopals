package main

import (
	"bytes"
	"math/rand"
	"time"
)

func MysteryEncryptHard(initialPad, ptext, key []byte) []byte {
	return MysteryEncrypt(append(initialPad, ptext...), key)
}

func main() {
	rand.Seed(time.Now().Unix())
	key := GenerateRandomByteSlice(16)
	secretPadding := GenerateRandomByteSlice(rand.Intn(5) + 5)

	//Detect length of secret padding
	pad := []byte{}
	encryptNothing := MysteryEncryptHard(secretPadding, pad, key)
	prevFirstBlock := encryptNothing[:16]
	for {
		pad = append(pad, byte(0))
		firstBlock := MysteryEncryptHard(secretPadding, pad, key)[:16]
		if bytes.Equal(prevFirstBlock, firstBlock) {
			break
		}
		prevFirstBlock = firstBlock
	}
	pad = pad[:len(pad)-1]
	//secretPadding + pad now is the length of a block
	secretPadLen := 16 - len(pad)
	mysteryLength := len(encryptNothing) - secretPadLen
	for i := 0; i < 15; i++ {
		pad := append(pad, byte(0))
	}
}
