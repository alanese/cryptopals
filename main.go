package main

import (
	cr "crypto/rand"
	"fmt"
	"math/big"
)

//ModInv computes the multiplicative inverse of x modulo m
//Returns nil if no inverse exists
func ModInv(x, m *big.Int) *big.Int {
	zero := big.NewInt(0)
	t := big.NewInt(0)
	newt := big.NewInt(1)
	r := big.NewInt(0).Set(m)
	newr := big.NewInt(0).Set(x)

	for zero.Cmp(newr) != 0 {
		q := big.NewInt(0).Div(r, newr)
		t, newt = newt, big.NewInt(0).Sub(t, big.NewInt(0).Mul(q, newt))
		r, newr = newr, big.NewInt(0).Sub(r, big.NewInt(0).Mul(q, newr))
	}

	if big.NewInt(1).Cmp(r) < 0 {
		return nil
	}
	if zero.Cmp(t) > 0 {
		t = t.Add(t, m)
	}
	return t
}

//GenerateRSAKeyPair generates RSA public and private keypairs
//using primes of the given bit length. Public key is [e, n],
//private key is [b, n]
func GenerateRSAKeyPair(pqbits int) (e *big.Int, d *big.Int, n *big.Int) {
	var p *big.Int
	var q *big.Int
	e = big.NewInt(3)
	zero := big.NewInt(0)
	one := big.NewInt(1)
	tmpMod := big.NewInt(0)
	//ensure p-1 %3 != 0
	for tmpMod.Cmp(zero) == 0 {
		p, _ = cr.Prime(cr.Reader, pqbits)
		tmpMod = tmpMod.Sub(p, one)
		tmpMod = tmpMod.Mod(tmpMod, e)
	}
	tmpMod = big.NewInt(0)
	//ensure q-1 %3 != 0
	for tmpMod.Cmp(zero) == 0 {
		q, _ = cr.Prime(cr.Reader, pqbits)
		tmpMod = tmpMod.Sub(q, one)
		tmpMod = tmpMod.Mod(tmpMod, e)
	}
	n = big.NewInt(0).Mul(p, q)
	pminus1 := big.NewInt(0).Sub(p, big.NewInt(1))
	qminus1 := big.NewInt(0).Sub(q, big.NewInt(1))
	et := big.NewInt(0).Mul(pminus1, qminus1)
	d = big.NewInt(0).ModInverse(e, et)
	return
}

//RSAEncrypt encrypts the byte slice msg using the RSA public
//keypair [e, n]
func RSAEncrypt(msg []byte, e, n *big.Int) []byte {
	msgNum := big.NewInt(0).SetBytes(msg)
	encryptedMsgNum := big.NewInt(0).Exp(msgNum, e, n)
	return encryptedMsgNum.Bytes()
}

//RSADecrypt decrypts the byte slice msg using the RSA private
//keypaid [d, n]
func RSADecrypt(msg []byte, d, n *big.Int) []byte {
	msgNum := big.NewInt(0).SetBytes(msg)
	decryptedMsgNum := big.NewInt(0).Exp(msgNum, d, n)
	return decryptedMsgNum.Bytes()
}

func main() {

	x := big.NewInt(842)
	m := big.NewInt(1337489)
	fmt.Println(ModInv(x, m))

	e, d, n := GenerateRSAKeyPair(40)

	msg := []byte{42}
	fmt.Println(msg)

	encrypted := RSAEncrypt(msg, e, n)

	decrypted := RSADecrypt(encrypted, d, n)
	fmt.Println(decrypted)

}
