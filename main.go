package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"
)

//C56Secret is the b64-encoded secret cookie for challenge 56
const C56Secret = "QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F"

//C56Oracle appends a secret cookie to the end of the given
//request and encrypts it with RC4 with a random 128-bit key
func C56Oracle(r []byte) []byte {
	cookie, _ := base64.StdEncoding.DecodeString(C56Secret)
	ptext := append(r, cookie...)
	key := GenerateRandomByteSlice(16)
	return EncryptRC4(ptext, key)
}

//C56GuessByte attempts to guess byte n of the secret cookie
func C56GuessByte(n, runs int) byte {
	prefix := make([]byte, 31-n)

	counter := make([]int, 256)

	for i := 0; i < runs; i++ {
		ctext := C56Oracle(prefix)
		counter[int(ctext[31])]++
	}

	maxCount := -1
	bestByte := byte(0)
	for i, v := range counter {
		if v > maxCount {
			maxCount = v
			bestByte = byte(i)
		}
	}

	return bestByte ^ 0xe0 //byte 31 of keystream biased towards 224
}

//C56GuessCookie guesses the secret cookie in challenge 56
func C56GuessCookie() []byte {
	guessedBytes := make([]byte, 30)
	for i := 0; i < 30; i++ {
		startTime := time.Now()
		guessedBytes[i] = C56GuessByte(i, 1<<24)
		endTime := time.Now()
		elapsedTime := endTime.Unix() - startTime.Unix()
		fmt.Printf("Byte %v elapsed time %vs\n", i, elapsedTime)
		fmt.Printf("%x\n%v\n", guessedBytes, string(guessedBytes))
	}
	return guessedBytes
}

func main() {
	//usually need this
	rand.Seed(time.Now().Unix())
	C56GuessCookie()

}
