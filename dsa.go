package main

import (
	cr "crypto/rand"
	"crypto/sha1"
	"fmt"
	"math/big"
)

//GenerateDSAKeyPair generates a private/public DSA keypair
//with the provided parameters
func GenerateDSAKeyPair(p, q, g *big.Int) (priv, pub *big.Int) {
	tmp := big.NewInt(0).Sub(q, big.NewInt(1))
	priv, _ = cr.Int(cr.Reader, tmp)
	priv.Add(priv, big.NewInt(1))
	pub = big.NewInt(0).Exp(g, priv, p)
	return
}

//DSASignSHA1 creates a DSA SHA-1 signature for the provided message
//with the provided parameters and private key and a randomly-chosen k
func DSASignSHA1(msg []byte, privKey, p, q, g *big.Int) (r, s *big.Int) {
	one := big.NewInt(1)

	qMinusOne := big.NewInt(0).Sub(q, one)

	for {
		k, _ := cr.Int(cr.Reader, qMinusOne)
		k.Add(k, one)
		r, s, err := DSASignSHA1Forcek(msg, k, privKey, p, q, g)
		if err != nil {
			continue
		}
		return r, s
	}
}

//DSASignSHA1Forcek creates a signature for the provided message
//with the provided parameters and private key and the chosen k.
//Returns a non-nil error if the chosen k results in r or s being zero.
func DSASignSHA1Forcek(msg []byte, k, privKey, p, q, g *big.Int) (r, s *big.Int, err error) {
	digest := sha1.Sum(msg)
	digestNum := big.NewInt(0).SetBytes(digest[:])
	r = big.NewInt(0).Exp(g, k, p)
	r.Mod(r, q)
	if big.NewInt(0).Cmp(r) == 0 {
		return nil, nil, fmt.Errorf("Invalid k")
	}

	kInv := big.NewInt(0).ModInverse(k, q)
	s = big.NewInt(0).Mul(privKey, r)
	s.Add(digestNum, s)
	s.Mul(kInv, s)
	s.Mod(s, q)

	if big.NewInt(0).Cmp(s) == 0 {
		return nil, nil, fmt.Errorf("Invalid k")
	}
	return r, s, nil
}

//VerifyDSASHA1Signature checks whether (r,s) is a valid DSA SHA-1 signature
//of msg with the provided parameters and public key
func VerifyDSASHA1Signature(msg []byte, r, s, pubKey, p, q, g *big.Int) bool {
	zero := big.NewInt(0)
	//Check r range
	if zero.Cmp(r) >= 0 || q.Cmp(r) <= 0 {
		return false
	}
	//Check s range
	if zero.Cmp(s) >= 0 || q.Cmp(s) <= 0 {
		return false
	}

	w := big.NewInt(0).ModInverse(s, q)
	h := sha1.Sum(msg)
	u1 := big.NewInt(0).SetBytes(h[:])
	u1.Mul(u1, w)
	u1.Mod(u1, q)
	u2 := big.NewInt(0).Mul(r, w)
	u2.Mod(u2, q)

	v := big.NewInt(0).Exp(g, u1, p)
	v2 := big.NewInt(0).Exp(pubKey, u2, p)
	v.Mul(v, v2)
	v.Mod(v, p)
	v.Mod(v, q)
	return v.Cmp(r) == 0

}
