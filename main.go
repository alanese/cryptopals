package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

//C38Server implements a simplified SRP server per challenge 38
func C38Server(in, out chan []byte) {
	password := "secret"
	g := big.NewInt(2)
	p, _ := big.NewInt(0).SetString(NIST1536GroupSize, 16)
	salt := GenerateRandomByteSlice(16)
	salted := append(salt, password...)
	xH := sha256.Sum256(salted)
	x := big.NewInt(0).SetBytes(xH[:])
	v := big.NewInt(0).Exp(g, x, p)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := GenerateNISTDHPrivateKey1536(rnd)
	B := big.NewInt(0).Exp(g, b, p)

	<-in //ignore username for this simple implementation
	A := big.NewInt(0).SetBytes(<-in)

	out <- salt
	out <- B.Bytes()
	uH := GenerateRandomByteSlice(16)
	out <- uH
	u := big.NewInt(0).SetBytes(uH)

	S := big.NewInt(0).Exp(v, u, p)
	S.Mul(S, A)
	S.Exp(S, b, p)
	K := sha256.Sum256(S.Bytes())

	hasher := hmac.New(sha256.New, K[:])
	trueHmac := hasher.Sum(salt)

	validateHmac := <-in

	if hmac.Equal(validateHmac, trueHmac) {
		out <- []byte("OK")
	} else {
		out <- []byte("ERROR")
	}

}

//C38Client implements a simplified SRP client per challenge 38
func C38Client(in, out chan []byte) bool {
	I := "bob"
	password := "pumbaa"
	p, _ := big.NewInt(0).SetString(NIST1536GroupSize, 16)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	a := GenerateNISTDHPrivateKey1536(rnd)
	A := GenerateNISTDHPublicKey1536(a)

	out <- []byte(I)
	out <- A.Bytes()

	salt := <-in
	B := big.NewInt(0).SetBytes(<-in)
	u := big.NewInt(0).SetBytes(<-in)

	salted := append(salt, password...)
	xH := sha256.Sum256(salted)
	x := big.NewInt(0).SetBytes(xH[:])
	exp := big.NewInt(0).Mul(u, x)
	exp.Add(a, exp)
	S := big.NewInt(0).Exp(B, exp, p)

	K := sha256.Sum256(S.Bytes())

	hasher := hmac.New(sha256.New, K[:])
	validateHmac := hasher.Sum(salt)
	out <- validateHmac

	resp := <-in

	return string(resp) == "OK"

}

//C38MITM cracks a simplified SRP password with a MITM attack.
//For simplicity, assumes the password is six lowercase letters
func C38MITM(in, out chan []byte) {
	p, _ := big.NewInt(0).SetString(NIST1536GroupSize, 16)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := GenerateNISTDHPrivateKey1536(rnd)
	B := GenerateNISTDHPublicKey1536(b)
	salt := GenerateRandomByteSlice(16)
	u := big.NewInt(0).SetBytes(GenerateRandomByteSlice(16))

	<-in //ignore username for this example
	A := big.NewInt(0).SetBytes(<-in)
	out <- salt
	out <- B.Bytes()
	out <- u.Bytes()

	targetHmac := <-in

	dhKey := big.NewInt(0).Exp(A, b, p)

	testPW := []byte{97, 97, 97, 97, 97, 97}
	for {
		fmt.Printf("Testing password %v\n", string(testPW))
		salted := append(salt, testPW...)
		xH := sha256.Sum256(salted)
		x := big.NewInt(0).SetBytes(xH[:])
		exp := big.NewInt(0).Mul(u, x)
		S := big.NewInt(0).Exp(B, exp, p)
		S.Mul(S, dhKey)
		S.Mod(S, p)
		K := sha256.Sum256(S.Bytes())
		hasher := hmac.New(sha256.New, K[:])
		testHmac := hasher.Sum(salt)
		if hmac.Equal(targetHmac, testHmac) {
			fmt.Printf("Found password: %v\n", string(testPW))
			out <- []byte("ERROR")
			return
		}
		testPW[0]++
		if testPW[0] > 122 {
			testPW[0] = 97
			testPW[1]++
			if testPW[1] > 122 {
				testPW[1] = 97
				testPW[2]++
				if testPW[2] > 122 {
					testPW[2] = 97
					testPW[3]++
					if testPW[3] > 122 {
						testPW[3] = 97
						testPW[4]++
						if testPW[4] > 122 {
							testPW[4] = 97
							testPW[5]++
							if testPW[5] > 122 {
								fmt.Printf("Failed to find password\n")
								out <- []byte("ERROR")
							}
						}
					}
				}
			}
		}

	}
}

func main() {

	cToM := make(chan []byte)
	mToC := make(chan []byte)
	go C38MITM(cToM, mToC)
	ok := C38Client(mToC, cToM)
	fmt.Println(ok)

}
