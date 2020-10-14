package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	//usually need these
	rand.Seed(time.Now().Unix())
	//key := GenerateRandomByteSlice(16)
	secretLen := rand.Intn(10) + 5
	secret := GenerateRandomByteSlice(secretLen)

	startMsg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")

	digest := MD4Hash(append(secret, startMsg...))

	forgedMsg, forgedHash := C30ForgeMAC(secret, startMsg, digest)
	targetHash := MD4Hash(append(secret, forgedMsg...))
	fmt.Printf("Forged message %X\n", forgedMsg)
	fmt.Printf("Actual hash %X\nTarget hash %X\n", forgedHash, targetHash)

}
