package main

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

//RSAParityOracle decrypts ciphertext with the RSA private
//key [d, n] and returns true iff the resulting plaintext is odd
func RSAParityOracle(ciphertext, d, n *big.Int) bool {
	plaintext := big.NewInt(0).Exp(ciphertext, d, n)
	return plaintext.Bit(0) != 0
}

//RSAParityAttack decrypts a ciphertext given a public RSA key [e,n]
//using a parity oracle. The private key d is passed in only to be
//passed to the oracle
func RSAParityAttack(ciphertext []byte, e, d, n *big.Int) []byte {
	two := big.NewInt(2)
	one := big.NewInt(1)
	cTextDouble := big.NewInt(0).Exp(two, e, n)
	testCText := big.NewInt(0).SetBytes(ciphertext)
	logn := n.BitLen()
	//this approach is ugly but avoids accumulating rounding errors
	divisor := big.NewInt(1)
	upperBd := big.NewInt(0).Set(n)
	upperBdDivided := big.NewInt(1)
	lowerBd := big.NewInt(0)
	lowerBdDivided := big.NewInt(0)
	for i := 0; i < logn; i++ {
		testCText.Mul(testCText, cTextDouble)
		testCText.Mod(testCText, n)

		fmt.Printf("Upper: %X\nLower: %X\n-------\n", upperBd, lowerBd)
		upperBdDivided.Mul(upperBdDivided, two)
		lowerBdDivided.Mul(lowerBdDivided, two)
		if RSAParityOracle(testCText, d, n) {
			lowerBdDivided.Add(lowerBdDivided, one)
		} else {
			upperBdDivided.Sub(upperBdDivided, one)
		}
		divisor.Mul(divisor, two)
		upperBd.Mul(upperBdDivided, n)
		upperBd.Div(upperBd, divisor)
		lowerBd.Mul(lowerBdDivided, n)
		lowerBd.Div(lowerBd, divisor)
	}
	return upperBd.Bytes()

}

func main() {
	rand.Seed(time.Now().Unix())

	secretMessage, err := base64.StdEncoding.DecodeString("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
	if err != nil {
		fmt.Println("error parsing base64")
	}
	e, d, n := GenerateRSAKeyPair(512)

	ciphertext := RSAEncrypt(secretMessage, e, n)
	broken := RSAParityAttack(ciphertext, e, d, n)
	fmt.Printf("Orig %v\nBrkn %v\n", string(secretMessage), string(broken))

}
