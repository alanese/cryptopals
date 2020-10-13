package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().Unix())
	key := GenerateRandomByteSlice(16)

	ecbCtext, err := DecodeFileBase64("25.txt")
	if err != nil {
		panic("failed decoding file")
	}
	ptext := DecryptAESECB(ecbCtext, []byte("YELLOW SUBMARINE"))
	nonce := make([]byte, 8) //use eight zero bytes as the nonce
	ptext = PKCSPad(ptext, 16)
	cText := EncryptAESCTR(ptext, key, nonce)

	decryptedText := C25BreakEdit(cText, key)
	fmt.Println(string(decryptedText))

}
