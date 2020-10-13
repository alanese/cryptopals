package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().Unix())
	key := GenerateRandomByteSlice(16)

	extractedKey := Challenge27ExtractKey(key)
	fmt.Printf("Guessed %X\n Actual %X\n", extractedKey, key)

}
