//This file contains functions implementing RSA keypair generation
//and encryption/decryption
package main

import (
	cr "crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
)

//RSASignatureDigestInfo implements the ASN.1 tag structure
//(incorrectly) of the DigestInfo type defined in RFC2313
//section 10.1.2. A correct implementation would have
//DigestAlgorithm as an AlgorithmIdentifier rather than an
//OID, but I don't really need parameters for what I'm doing
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

//GenerateRSAKeyPair generates RSA public and private keypairs
//using primes of the given bit length. Public key is [e, n],
//private key is [d, n]
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

//RSAEncryptPad encrypts the byte slice msg using the RSA public
//keypair [e, n] and pads the result to the length of n (rounded
//up to the next byte)
func RSAEncryptPad(msg []byte, e, n *big.Int) []byte {
	encrypted := RSAEncrypt(msg, e, n)
	padding := make([]byte, len(n.Bytes())-len(encrypted))
	padded := append(padding, encrypted...)
	return padded
}

//RSADecrypt decrypts the byte slice msg using the RSA private
//keypair [d, n]
func RSADecrypt(msg []byte, d, n *big.Int) []byte {
	msgNum := big.NewInt(0).SetBytes(msg)
	decryptedMsgNum := big.NewInt(0).Exp(msgNum, d, n)
	return decryptedMsgNum.Bytes()
}

//RSADecryptPad decrypts the byte slice msg using the RSA private
//keypair [d, n] and pads the result to the length of n (rounded
//up to the next byte)
func RSADecryptPad(msg []byte, d, n *big.Int) []byte {
	decrypted := RSADecrypt(msg, d, n)
	padding := make([]byte, len(n.Bytes())-len(decrypted))
	padded := append(padding, decrypted...)
	return padded
}
