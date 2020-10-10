package main

import (
	"bytes"
	"fmt"
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
	padLength := len(pad)
	//secretPadding + pad now is the length of a block
	secretPadLen := 16 - len(pad)
	mysteryLength := len(encryptNothing) - secretPadLen
	for i := 0; i < 15; i++ {
		pad = append(pad, byte(0))
	}
	for i := 0; i < mysteryLength; i++ {
		currentBlock := i/16 + 1
		byteInBlock := i % 16

		targetHead := pad[byteInBlock : padLength+15]
		targetCtext := MysteryEncryptHard(secretPadding, targetHead, key)

		for j := 0; j < 256; j++ {
			testHead := append(pad[byteInBlock:], byte(j))
			testCText := MysteryEncryptHard(secretPadding, testHead, key)
			if bytes.Equal(targetCtext[currentBlock*16:(currentBlock+1)*16],
				testCText[currentBlock*16:(currentBlock+1)*16]) {
				pad = append(pad, byte(j))
				//fmt.Println(string(pad[padLength+15:])) //Uncomment this line to see the text decrypted one byte at a time!
				break
			}
		}

	}
	fmt.Println(string(pad)[padLength+15:])
}
