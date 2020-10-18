package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

//DHEchoBob implements an "echo" bot. To use:
//Start as a goroutine, then send the chosen prime, the chosen generator, and
//Alice's public key over in. Read Bob's public key from out.
//Send a message encrypted with AES-CBC with the IV appended to the end over in
//Read the echoed message, encrypted similarly, from out.
//Close in to terminate the conversation - this will cause Bob to close out
//and end
func DHEchoBob(in, out chan []byte) {
	rSource := rand.New(rand.NewSource(time.Now().UnixNano()))
	pBytes := <-in
	p := big.NewInt(0).SetBytes(pBytes)
	gBytes := <-in
	g := big.NewInt(0).SetBytes(gBytes)
	b := GenerateDHPrivateKey(rSource, p)
	B := GenerateDHPublicKey(b, p, g)
	aBytes := <-in
	A := big.NewInt(0)
	A.SetBytes(aBytes)
	out <- B.Bytes()
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

//C34Mallory implements a MITM attack on Diffie-Hellman key exchange.
//Alice must initiate the key exchange, but once it is complete either
//Alice or Bob can send a message; Mallory will read the message and pass it on
//to the other party.  Run as a goroutine. Close either in channel to close both
//out channels and terminate.
func C34Mallory(aliceIn, aliceOut, bobIn, bobOut chan []byte) {
	pBytes := <-aliceIn
	gBytes := <-aliceIn
	_ = <-aliceIn
	bobOut <- pBytes
	bobOut <- gBytes
	bobOut <- pBytes
	_ = <-bobIn
	aliceOut <- pBytes
	sharedSecret := big.NewInt(0)
	secretHash := sha256.Sum256(sharedSecret.Bytes())
	key := secretHash[:16]

	for {
		select {
		case aliceMsg, ok := <-aliceIn:
			if !ok {
				close(aliceOut)
				close(bobOut)
				return
			}
			iv := aliceMsg[len(aliceMsg)-16:]
			encrypted := aliceMsg[:len(aliceMsg)-16]
			decrypted := DecryptAESCBC(encrypted, key, iv)
			decrypted, _ = StripPKCS7Padding(decrypted, 16)
			fmt.Printf("MALLORY: Intercepted message from Alice to Bob: %v\n", string(decrypted))
			bobOut <- aliceMsg
		case bobMsg, ok := <-bobIn:
			if !ok {
				close(aliceOut)
				close(bobOut)
				return
			}
			iv := bobMsg[len(bobMsg)-16:]
			decrypted := DecryptAESCBC(bobMsg[:len(bobMsg)-16], key, iv)
			decrypted, _ = StripPKCS7Padding(decrypted, 16)
			fmt.Printf("MALLORY: Intercepted message from Bob to Alice: %v\n", string(decrypted))
			aliceOut <- bobMsg

		}
	}

}

func main() {
	//usually need these
	rand.Seed(time.Now().Unix())
	//key := GenerateRandomByteSlice(16)
	p, _ := big.NewInt(0).SetString(groupSizeString, 16)
	g := big.NewInt(2)
	aToM := make(chan []byte)
	mToA := make(chan []byte)
	bToM := make(chan []byte)
	mToB := make(chan []byte)
	go DHEchoBob(mToB, bToM)
	go C34Mallory(aToM, mToA, bToM, mToB)
	rSource := rand.New(rand.NewSource(time.Now().UnixNano()))
	a := GenerateDHPrivateKey(rSource, p)
	A := GenerateDHPublicKey(a, p, g)
	aToM <- p.Bytes()
	aToM <- g.Bytes()
	aToM <- A.Bytes()
	bBytes := <-mToA
	B := big.NewInt(0).SetBytes(bBytes)
	key1, _ := NISTDiffieHellmanKeys(B, a)
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
