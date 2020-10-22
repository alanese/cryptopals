package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

//RSASignatureDigestInfo implements the ASN.1 tag structure
//(incorrectly) of the DigestInfo type defined in RFC2313
//section 10.1.2. A correct implementation would have
//DigestAlgorithm as an AlgorithmIdentifier rather than an
//OID, but I don't have access to that definition, and I
//don't really need the details for what I'm doing anyway
type RSASignatureDigestInfo struct {
	DigestAlgorithm asn1.ObjectIdentifier
	Digest          []byte
}

var sha256OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

//UnmarshalDigestInfo interprets a byte slice in ASN.1 format
//as an instance of RSASignatureDigestInfo
func UnmarshalDigestInfo(b []byte) RSASignatureDigestInfo {
	r := RSASignatureDigestInfo{}
	asn1.Unmarshal(b, &r)
	return r
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

//RSASign generates an RSA signature for msg with the private
//keypair [d, n]. This pads per PKCS1.5, but doesn't quite encode the digest
//according to the standard - see comment on RSASignatureDigestInfo
func RSASign(msg []byte, d, n *big.Int) []byte {
	digest := sha256.Sum256(msg)
	digestinfo, _ := asn1.Marshal(RSASignatureDigestInfo{sha256OID, digest[:]})

	paddingLength := len(n.Bytes()) - len(digestinfo)
	padding := make([]byte, paddingLength)
	padding[1] = 0x01
	for i := 2; i < paddingLength-1; i++ {
		padding[i] = 0xFF
	}
	D := append(padding, digestinfo...)
	signature := RSADecryptPad(D, d, n)
	return signature
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

func main() {
	rand.Seed(time.Now().Unix())

	msg := []byte("hi mom")
	e, d, n := GenerateRSAKeyPair(1024)

	sig := RSASign(msg, d, n)

	ok := C42CheckRSASignature(msg, sig, e, n)
	fmt.Println(ok)

	forgedSig := C42ForgeSignature(msg, n)

	ok = C42CheckRSASignature(msg, forgedSig, e, n)
	fmt.Println(ok)

}
