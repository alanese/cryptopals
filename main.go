package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().Unix())
	//key := GenerateRandomByteSlice(16)
	testLength := rand.Intn(10) + 7
	origText := GenerateRandomByteSlice(testLength)
	paddedText := PKCSPad(origText, 16)
	unPaddedText, _ := StripPKCS7Padding(paddedText, 16)
	fmt.Printf("%X\n%X\n%X\n", origText, paddedText, unPaddedText)
}
