package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"time"
)

//C37UserData holds the data necessary for the SRP password
//verification scheme per challenge 37
type C37UserData struct {
	username string
	password string
	salt     []byte
	v        *big.Int
	A        *big.Int
	B        *big.Int
	u        *big.Int
}

//NIST1536GroupSize is the order of the 1536-bit MODP group defined in RFC 3526
const NIST1536GroupSize = "ffffffffffffffffc90fdaa22168c234" +
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

var c37k = big.NewInt(3) //SRP parameter
var c37g = big.NewInt(2) //NIST-standard generator for 1536-bit MODP
var c37p, _ = big.NewInt(0).SetString(NIST1536GroupSize, 16)
var c37Users map[string]*C37UserData

var c37b *big.Int

//GenerateDHPrivateKey generates a random private key
//suitable for use with finite-field Diffie-Hellman
//with the given prime p. This implementation does NOT use
//a cryptographically-secure RNG, so don't use it for anything
//real
func GenerateDHPrivateKey(rnd *rand.Rand, p *big.Int) *big.Int {
	q := big.NewInt(0).SetBytes(p.Bytes())
	q.Sub(q, big.NewInt(1))
	q.Div(q, big.NewInt(2))

	q.Sub(q, big.NewInt(1))
	q.Rand(rnd, q)
	q.Add(q, big.NewInt(1))

	return q
}

//GenerateNISTDHPrivateKey1536 generates a random private key
//suitable for use with the 1536-bit MODP group defined in
//RFC-3526 section 2. This implementation does NOT use a
//cryptographically-secure RNG, so don't use it for anything real.
func GenerateNISTDHPrivateKey1536(rnd *rand.Rand) *big.Int {
	q, _ := big.NewInt(0).SetString(NIST1536GroupSize, 16)

	return GenerateDHPrivateKey(rnd, q)
}

//GenerateRandomByteSlice generates a random slice
//of bytes of the given length
func GenerateRandomByteSlice(length int) []byte {
	s := make([]byte, length)
	for i := range s {
		s[i] = byte(rand.Intn(256))
	}
	return s
}

//C37GenerateB implements the first C->S->C exchange of an
//SRP password verification scheme
func C37GenerateB(w http.ResponseWriter, rq *http.Request) {
	I := rq.URL.Query().Get("u")
	A, ok := big.NewInt(0).SetString(rq.URL.Query().Get("A"), 16)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Malformed A"))
		return
	}
	d, ok := c37Users[I]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error"))
		return
	}
	d.A = A
	if d.salt == nil {
		d.salt = GenerateRandomByteSlice(16)
		salted := append((*d).salt, (*d).password...)
		xH := sha256.Sum256(salted)
		x := big.NewInt(0).SetBytes(xH[:])
		d.v = x.Exp(c37g, x, c37p)
	}

	v := d.v

	B := big.NewInt(0).Exp(c37g, c37b, c37p)
	t0 := big.NewInt(0).Mul(c37k, v)
	B.Add(B, t0)
	B.Mod(B, c37p)
	d.B = B
	w.Write(append(d.salt, B.Bytes()...))
	uH := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
	u := big.NewInt(0).SetBytes(uH[:])
	d.u = u
}

//C37VerifyHash implements the verification component of an SRP
//password verification scheme
func C37VerifyHash(w http.ResponseWriter, rq *http.Request) {
	I := rq.URL.Query().Get("u")
	d, ok := c37Users[I]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error"))
		return
	}

	S := big.NewInt(0).Exp(d.v, d.u, c37p)
	S.Mul(S, d.A)
	S.Exp(S, c37b, c37p)
	K := sha256.Sum256(S.Bytes())

	hasher := hmac.New(sha256.New, K[:])

	trueHmac := hasher.Sum(d.salt)
	signature, err := hex.DecodeString(rq.URL.Query().Get("signature"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Malformed signature"))
		return
	}

	if hmac.Equal(trueHmac, signature) {
		w.Write([]byte("OK"))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error"))
	}
}

//C37StartServer starts the server side of an
//SRP password verification scheme, per challenge 37
func C37StartServer() {
	http.HandleFunc("/getB", C37GenerateB)
	http.HandleFunc("/validate", C37VerifyHash)
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}

func main() {
	c37b = GenerateNISTDHPrivateKey1536(rand.New(rand.NewSource(time.Now().UnixNano())))
	c37Users = make(map[string]*C37UserData)
	c37Users["bob"] = &C37UserData{username: "bob", password: "secretpassword123", salt: nil}
	C37StartServer()
}
