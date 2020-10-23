package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
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

//C42CheckHash determines whether the digest in digestInfo is the SHA-256 digest
//produced by msg
func C42CheckHash(digestinfo RSASignatureDigestInfo, msg []byte) bool {
	verifyHash := digestinfo.Digest
	targetHash := sha256.Sum256(msg)
	return bytes.Equal(verifyHash, targetHash[:])
}

//C42CheckRSASignature determines (incorrectly) if rsaSignature is a properly
//padded and encrypted RSA SHA-256 signature for msg; the function does not
//properly ensure the padding is long enough, enabling Bleichenbacher's attack
//for sufficiently long n
func C42CheckRSASignature(msg []byte, rsaSignature []byte, e, n *big.Int) bool {
	sig := RSAEncryptPad(rsaSignature, e, n)

	notPadding := 0
	padding00 := 1
	padding0001 := 2
	paddingFF := 3
	state := 0
	i := 0
	//I feel like there's a better way to do this than essentially implementing a DFA
	for i < len(sig) {
		switch state {
		case notPadding:
			if sig[i] == 0x00 {
				state = padding00
			}
		case padding00:
			if sig[i] == 0x01 {
				state = padding0001
			} else {
				state = notPadding
			}
		case padding0001:
			if sig[i] == 0x00 {
				digestInfo := UnmarshalDigestInfo(sig[i+1:])
				return C42CheckHash(digestInfo, msg) //deliberately fail to check right-justification
			} else if sig[i] == 0xFF {
				state = paddingFF
			} else {
				state = notPadding
			}
		case paddingFF:
			if sig[i] == 0x00 {
				digestInfo := UnmarshalDigestInfo(sig[i+1:])
				return C42CheckHash(digestInfo, msg) //deliberately fail to check right-justification
			} else if sig[i] != 0xFF {
				state = notPadding
			}
		default:
			panic("Unexpected state error") //this shouldn't happen

		}
		i++
	}
	return false

}

//C42ForgeSignature forges an e=3 RSA signature for the given message
//via a flawed padding check in the verifier. This will fail if n isn't
//at least roughly three times the length of the encoded ASN data (47 bytes)
func C42ForgeSignature(msg []byte, n *big.Int) []byte {
	dataLength := len(n.Bytes())
	digest := sha256.Sum256(msg)
	asnData, _ := asn1.Marshal(RSASignatureDigestInfo{sha256OID, digest[:]})
	fmt.Println(len(asnData))

	padding := make([]byte, dataLength/3-len(asnData))
	padding[1] = 0x01
	for i := 2; i < len(padding)-1; i++ {
		padding[i] = 0xFF
	}
	dHead := append(padding, asnData...)
	garbageLength := dataLength - len(dHead)
	garbage := GenerateRandomByteSlice(garbageLength)
	forgedD := append(dHead, garbage...)
	forgedDNum := big.NewInt(0).SetBytes(forgedD)
	forgedSigNum := NRoot(forgedDNum, 3)
	forgedSig := forgedSigNum.Bytes()
	return forgedSig
}

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
