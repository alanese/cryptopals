package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().Unix())
	origMsg := []byte("from=123&to=456&amount=1000000")
	origIV := GenerateRandomByteSlice(16)
	secretKey := GenerateRandomByteSlice(16)

	origMac := AESCBCMAC(origMsg, origIV, secretKey)

	newMsg, newIv := C49ForgeMessage(origMsg, origIV)
	fmt.Printf("Old IV: %X\nNew IV: %X\n", origIV, newIv)
	fmt.Println(string(newMsg))

	fmt.Println(VerifyAESCBCMAC(origMac, newMsg, newIv, secretKey))

}
