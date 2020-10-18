package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

//DHEchoBob implements an "echo" bot. To use:
//Start as a goroutine, then send Alice's DH public
//key over in. Read Bob's public key from out.
//Send a message encrypted with AES-CBC with the IV appended to the end over in
//Read the echoed message, encrypted similarly, from out
func DHEchoBob(in, out chan []byte) {
	rSource := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := GenerateNISTDHPrivateKey(rSource)
	aBytes := <-in
	A := big.NewInt(0)
	A.SetBytes(aBytes)
	out <- b.Bytes()
	key1, _ := NISTDiffieHellmanKeys(A, b)
	for {
		v, ok := <-in
		if !ok {
			close(out)
			break
		}
		iv := v[len(v)-16:]
		aMsgEncrypted := v[:len(v)-16]
		aMsg := DecryptAESCBC(aMsgEncrypted, key1, iv)
		aMsg, _ = StripPKCS7Padding(aMsg, 16)
		fmt.Printf("BOB: Decrypted message from Alice: %v\n", string(aMsg))
		bobIv := GenerateRandomByteSlice(16)
		aMsg = PKCSPad(aMsg, 16)
		bMsgEncrypted := EncryptAESCBC(aMsg, key1, bobIv)
		bMsgEncrypted = append(bMsgEncrypted, bobIv...)
		out <- bMsgEncrypted

	}
}

func main() {
	//usually need these
	rand.Seed(time.Now().Unix())
	//key := GenerateRandomByteSlice(16)
	aToB := make(chan []byte)
	bToA := make(chan []byte)
	go DHEchoBob(aToB, bToA)
	rSource := rand.New(rand.NewSource(time.Now().UnixNano()))
	a := GenerateNISTDHPrivateKey(rSource)
	aToB <- a.Bytes()
	bBytes := <-bToA
	B := big.NewInt(0).SetBytes(bBytes)
	key1, _ := NISTDiffieHellmanKeys(B, a)
	message := []byte("TOP SECRET MESSAGE DON'T TELL ANYONE")
	message = PKCSPad(message, 16)
	iv := GenerateRandomByteSlice(16)
	encryptedMsg := EncryptAESCBC(message, key1, iv)
	encryptedMsg = append(encryptedMsg, iv...)
	aToB <- encryptedMsg

	encryptedMsg = <-bToA
	iv = encryptedMsg[len(encryptedMsg)-16:]
	encryptedMsg = encryptedMsg[:len(encryptedMsg)-16]
	decryptedMsg := DecryptAESCBC(encryptedMsg, key1, iv)
	decryptedMsg, _ = StripPKCS7Padding(decryptedMsg, 16)
	fmt.Printf("ALICE: Decrypted message from Bob: %v\n", string(decryptedMsg))
	close(aToB)

}
