package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	//usually need these
	rand.Seed(time.Now().Unix())
	key := GenerateRandomByteSlice(16)

	message := []byte("SECRET MESSAGE DON'T TELL ANYBODY")
	notMessage := []byte("SECRET MESSAGE TELL EVERYBODY NOW")
	notKey := []byte("AAAAAAAAAAAAAAAASECRET MESSAGE DON'T TELL ANYBODY")
	fmt.Printf("%X\n", SHA1MAC(message, key))
	fmt.Printf("%X\n", SHA1MAC(notMessage, key))
	fmt.Printf("%X\n", SHA1Hash(notKey))

}
