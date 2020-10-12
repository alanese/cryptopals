package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().Unix())
	key := GenerateRandomByteSlice(16)
	iv := GenerateRandomByteSlice(16)
	ctext := Challenge17Encrypt(key, iv)
	e := Challenge17Decrypt(ctext, key, iv)
	if e == nil {
		fmt.Println("Decrypt ok")
	}
	knownBlocksReverse := [][]byte{}
	for len(ctext) > 16 {
		lastBlock := Challenge17GetLastBlock(ctext, key, iv)
		knownBlocksReverse = append(knownBlocksReverse, lastBlock)
		ctext = ctext[:len(ctext)-16]
	}
	pText := []byte{}
	for i := len(knownBlocksReverse) - 1; i >= 0; i-- {
		pText = append(pText, knownBlocksReverse[i]...)
	}
	pText, _ = StripPKCS7Padding(pText, 16)
	fmt.Println(string(pText))

}
