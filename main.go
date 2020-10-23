package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

//C45MagicSignature generates a magic signature that will validate against
//any string for a domain parameter g congruent to 1 mod p
func C45MagicSignature(pubKey, p, q *big.Int) (r, s *big.Int) {
	z := big.NewInt(5)
	r = big.NewInt(0).Exp(pubKey, z, p)
	r.Mod(r, q)

	zInv := big.NewInt(0).ModInverse(z, q)
	s = big.NewInt(0).Mul(r, zInv)
	s.Mod(s, q)
	return
}

func main() {
	rand.Seed(time.Now().Unix())

	p, _ := big.NewInt(0).SetString(C43pString, 16)
	g := big.NewInt(0).Add(p, big.NewInt(1))
	q, _ := big.NewInt(0).SetString(C43qString, 16)

	_, pub := GenerateDSAKeyPair(p, q, g)

	msg := []byte("yubi yubi")
	r, s := C45MagicSignature(pub, p, q)
	fmt.Printf("r %X\ns %X\n", r, s)

	ok := VerifyDSASHA1Signature(msg, r, s, pub, p, q, g)
	fmt.Println(ok)

}
