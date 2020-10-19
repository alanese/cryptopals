package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

func main() {
	//usually need these
	rand.Seed(time.Now().Unix())
	//key := GenerateRandomByteSlice(16)
	p, _ := big.NewInt(0).SetString(groupSizeString, 16)
	g := big.NewInt(2)
	aToM := make(chan []byte)
	mToA := make(chan []byte)
	mToB := make(chan []byte)
	bToM := make(chan []byte)
	go C35EchoBob(mToB, bToM)
	go C35Mallory(aToM, mToA, bToM, mToB)
	aToM <- p.Bytes()
	aToM <- g.Bytes()
	<-mToA
	g = big.NewInt(0).SetBytes(<-mToA)
	rSource := rand.New(rand.NewSource(time.Now().UnixNano()))
	a := GenerateDHPrivateKey(rSource, p)
	A := GenerateDHPublicKey(a, p, g)
	aToM <- A.Bytes()
	bBytes := <-mToA
	B := big.NewInt(0).SetBytes(bBytes)
	key1, _ := DiffieHellmanKeys(B, a, p)
	message := []byte("TOP SECRET MESSAGE DON'T TELL ANYONE")
	message = PKCSPad(message, 16)
	iv := GenerateRandomByteSlice(16)
	encryptedMsg := EncryptAESCBC(message, key1, iv)
	encryptedMsg = append(encryptedMsg, iv...)
	aToM <- encryptedMsg

	encryptedMsg = <-mToA
	iv = encryptedMsg[len(encryptedMsg)-16:]
	encryptedMsg = encryptedMsg[:len(encryptedMsg)-16]
	decryptedMsg := DecryptAESCBC(encryptedMsg, key1, iv)
	decryptedMsg, _ = StripPKCS7Padding(decryptedMsg, 16)
	fmt.Printf("ALICE: Decrypted message from Bob: %v\n", string(decryptedMsg))
	close(aToM)

}
