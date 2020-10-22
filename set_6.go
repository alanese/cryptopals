package main

import (
	"bytes"
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
