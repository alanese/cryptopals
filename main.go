package main

import (
	"fmt"
	"math/big"
)

//C41Recovery implements an unpadded message recovery attack
func C41Recovery(ctext []byte, e, d, n *big.Int) {

	s := big.NewInt(5)
	c := big.NewInt(0).SetBytes(ctext)

	cprime := big.NewInt(0).Exp(s, e, n)
	cprime.Mul(cprime, c)
	cprime.Mod(cprime, n)

	pprime := big.NewInt(0).SetBytes(RSADecrypt(cprime.Bytes(), d, n))

	sInv := big.NewInt(0).ModInverse(s, n)
	p := big.NewInt(0).Mul(pprime, sInv)
	p = p.Mod(p, n)
	msg := p.Bytes()

	fmt.Printf("Dcrypted message: %v\n", string(msg))

}

func main() {
	msg := []byte("SECRETMSG")

	e, d, n := GenerateRSAKeyPair(128)
	ctext := RSAEncrypt(msg, e, n)
	C41Recovery(ctext, e, d, n)

}
