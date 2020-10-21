package main

import (
	"fmt"
	"math/big"
)

//C40BreakRSA encrypts the given message three times using three
//randomly-generated RSA public keys, then breaks the encryption
func C40BreakRSA(msg []byte) {
	e1, _, n1 := GenerateRSAKeyPair(64)
	e2, _, n2 := GenerateRSAKeyPair(64)
	e3, _, n3 := GenerateRSAKeyPair(64)

	encrypted1 := big.NewInt(0).SetBytes(RSAEncrypt(msg, e1, n1))
	encrypted2 := big.NewInt(0).SetBytes(RSAEncrypt(msg, e2, n2))
	encrypted3 := big.NewInt(0).SetBytes(RSAEncrypt(msg, e3, n3))

	ms1 := big.NewInt(0).Mul(n2, n3)
	ms2 := big.NewInt(0).Mul(n1, n3)
	ms3 := big.NewInt(0).Mul(n1, n2)
	inv1 := big.NewInt(0).ModInverse(ms1, n1)
	inv2 := big.NewInt(0).ModInverse(ms2, n2)
	inv3 := big.NewInt(0).ModInverse(ms3, n3)

	res1 := big.NewInt(0).Mul(encrypted1, ms1)
	res1.Mul(res1, inv1)
	res2 := big.NewInt(0).Mul(encrypted2, ms2)
	res2.Mul(res2, inv2)
	res3 := big.NewInt(0).Mul(encrypted3, ms3)
	res3.Mul(res3, inv3)

	tot := big.NewInt(0).Add(res1, res2)
	tot.Add(tot, res3)

	totalMod := big.NewInt(0).Mul(n1, n2)
	totalMod.Mul(totalMod, n3)

	tot.Mod(tot, totalMod)

	decrypted := NRoot(tot, 3)

	decryptedH := decrypted.Bytes()

	fmt.Printf("Original bytes: %X\n", msg)
	fmt.Printf("Dcrypted bytes: %X\n", decryptedH) //Typo is intentional for alignment
	fmt.Printf("Original message %v\n", string(msg))
	fmt.Printf("Dcrypted message %v\n", string(decryptedH))

}

func main() {

	msg := []byte("SECRETMSG")
	C40BreakRSA(msg)

}
