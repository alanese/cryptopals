package main

import (
	"crypto/sha256"
	"math/big"
	"math/rand"
)

//Order of the 1536-bit MODP group defined in RFC 3526
const groupSizeString = "ffffffffffffffffc90fdaa22168c234" +
	"c4c6628b80dc1cd129024e088a67cc74" +
	"020bbea63b139b22514a08798e3404dd" +
	"ef9519b3cd3a431b302b0a6df25f1437" +
	"4fe1356d6d51c245e485b576625e7ec6" +
	"f44c42e9a637ed6b0bff5cb6f406b7ed" +
	"ee386bfb5a899fa5ae9f24117c4b1fe6" +
	"49286651ece45b3dc2007cb8a163bf05" +
	"98da48361c55d39a69163fa8fd24cf5f" +
	"83655d23dca3ad961c62f356208552bb" +
	"9ed529077096966d670c354e4abc9804" +
	"f1746c08ca237327ffffffffffffffff"

//ModExp computes (a**x) mod m
func ModExp(a, x, m *big.Int) (r *big.Int) {
	accum := big.NewInt(1)
	expLength := x.BitLen()
	for i := 0; i < expLength; i++ {
		accum.Mul(accum, accum)
		if x.Bit(i) != 0 {
			accum.Mul(accum, a)
		}
		accum.Mod(accum, m)
	}
	return accum

}

//GenerateNISTDHPublicKey generates a Diffie-Hellman
//public key A from a private key a using the 1536-bit
//MODP group defined in RFC-3526 section 2
func GenerateNISTDHPublicKey(a *big.Int) *big.Int {
	p := big.NewInt(0)
	p.SetString(groupSizeString, 16)

	g := big.NewInt(2)
	return ModExp(g, a, p)
}

//GenerateNISTDHPrivateKey generates a random private key
//suitable for use with the 1536-bit MODP group defined in
//RFC-3526 section 2. This implementation does NOT use a
//cryptographically-secure RNG, so don't use it for anything real.
func GenerateNISTDHPrivateKey(rnd *rand.Rand) *big.Int {
	q := big.NewInt(0)
	q.SetString(groupSizeString, 16)
	q.Sub(q, big.NewInt(1))
	q.Div(q, big.NewInt(2)) //q = (p-1)/2

	q.Sub(q, big.NewInt(1))
	q.Rand(rnd, q)          //generate a random number from 0 to (p-1)/2 - 2
	q.Add(q, big.NewInt(1)) //1 to (p-1)/2 - 1

	return q

}

//NISTDiffieHellmanKeys generates two 128-bit keys using
//the receiver's public key A and the sender's private key b,
//using the 1536-bit MODP group defined in RFC-3526 section 2
func NISTDiffieHellmanKeys(A, b *big.Int) ([]byte, []byte) {
	m := big.NewInt(0)
	m.SetString(groupSizeString, 16)
	sharedSecret := ModExp(A, b, m)
	secretHash := sha256.Sum256(sharedSecret.Bytes())
	return secretHash[:16], secretHash[16:]
}
