package main

import (
	cr "crypto/rand"
	"crypto/sha1"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

//C43pString is a hex representation of the p parameter used
//for challenge 43
var C43pString = "800000000000000089e1855218a0e7da" +
	"c38136ffafa72eda7859f2171e25e65e" +
	"ac698c1702578b07dc2a1076da241c76" +
	"c62d374d8389ea5aeffd3226a0530cc5" +
	"65f3bf6b50929139ebeac04f48c3c84a" +
	"fb796d61e5a4f9a8fda812ab59494232" +
	"c7d2b4deb50aa18ee9e132bfa85ac437" +
	"4d7f9091abc3d015efc871a584471bb1"

//C43qString is a hex representation of the q parameter used
//for challenge 43
var C43qString = "f4f47f05794b256174bba6e9b396a7707e563c5b"

//C43gString is a hex representation of the g parameter used for challenge 43
var C43gString = "5958c9d3898b224b12672c0b98e06c60" +
	"df923cb8bc999d119458fef538b8fa40" +
	"46c8db53039db620c094c9fa077ef389" +
	"b5322a559946a71903f990f1f7e0e025" +
	"e2d7f7cf494aff1a0470f5b64c36b625" +
	"a097f1651fe775323556fe00b3608c88" +
	"7892878480e99041be601a62166ca689" +
	"4bdd41a7054ec89f756ba9fc95302291"

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
//with the provided parameters and private key
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

//C43CrackPrivateKey finds a DSA private key given a message,
//a SHA-1 DSA signature of that message (signed with a private key generated
//with a flawed algorithm), and the provided DSA parameters.
func C43CrackPrivateKey(msg []byte, r, s, p, q, g *big.Int) *big.Int {
	hBytes := sha1.Sum(msg)
	h := big.NewInt(0).SetBytes(hBytes[:])
	//find k
	k := big.NewInt(0)
	testR := big.NewInt(0)
	for testK := int64(0); testK <= int64(1<<16); testK++ {
		k.SetInt64(testK)
		testR.Exp(g, k, p)
		testR.Mod(testR, q)
		if r.Cmp(testR) == 0 {
			break
		}
	}

	rInv := big.NewInt(0).ModInverse(r, q)
	tmp := big.NewInt(0).Mul(s, k)
	tmp.Sub(tmp, h)
	tmp.Mul(tmp, rInv)
	x := big.NewInt(0).Mod(tmp, q)
	return x

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

func main() {
	rand.Seed(time.Now().Unix())

	p, _ := big.NewInt(0).SetString(C43pString, 16)
	g, _ := big.NewInt(0).SetString(C43gString, 16)
	q, _ := big.NewInt(0).SetString(C43qString, 16)

	rStr := "548099063082341131477253921760299949438196259240"
	sStr := "857042759984254168557880549501802188789837994940"

	r, _ := big.NewInt(0).SetString(rStr, 10)
	s, _ := big.NewInt(0).SetString(sStr, 10)

	lyrics := []byte("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n")

	privKey := C43CrackPrivateKey(lyrics, r, s, p, q, g)
	pkBytes := []byte(fmt.Sprintf("%x", privKey))
	pkHash := sha1.Sum(pkBytes)
	fmt.Printf("%X\n", pkHash)

}
