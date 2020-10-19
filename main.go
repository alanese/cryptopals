package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

func SRPServer(in, out chan []byte) {
	g := big.NewInt(2)
	k := big.NewInt(3)
	p, _ := big.NewInt(0).SetString(NIST1536GroupSize, 16)
	b := GenerateNISTDHPrivateKey1536(rand.New(rand.NewSource(time.Now().UnixNano())))
	salt := GenerateRandomByteSlice(16)
	password := "secretpassword123"
	salted := append(salt, []byte(password)...)
	xH := sha256.Sum256(salted)
	x := big.NewInt(0).SetBytes(xH[:])
	//v := big.NewInt(0).Exp(g, x, p)
	v := ModExp(g, x, p)
	//Pretend to forget x, xH

	<-in //Ignore email - we're not doing multiple clients yet
	A := big.NewInt(0).SetBytes(<-in)
	out <- salt
	B := big.NewInt(0).Exp(g, b, p) //g**b % p
	tmp := big.NewInt(0).Mul(k, v)
	B.Add(B, tmp) //kv + (g**b %p)
	B.Mod(B, p)   //kv + g**b % p
	out <- B.Bytes()

	uH := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
	u := big.NewInt(0).SetBytes(uH[:])
	//good to here
	t0 := big.NewInt(0).Mul(A, big.NewInt(0).Exp(v, u, p))
	S := big.NewInt(0).Exp(t0, b, p)
	K := sha256.Sum256(S.Bytes())

	providedHmac := <-in

	hmacHasher := hmac.New(sha256.New, K[:])
	realHmac := hmacHasher.Sum(salt)
	if hmac.Equal(providedHmac, realHmac) {
		out <- []byte("OK")
	} else {
		out <- []byte("ERROR")
	}

}

func SRPClient(in, out chan []byte) []byte {
	g := big.NewInt(2)
	k := big.NewInt(3)
	p, _ := big.NewInt(0).SetString(NIST1536GroupSize, 16)
	a := GenerateNISTDHPrivateKey1536(rand.New(rand.NewSource(time.Now().UnixNano())))

	A := big.NewInt(0).Exp(g, a, p)
	email := "bob@example.com"
	password := "secretpassword123"
	out <- []byte(email)
	out <- A.Bytes()
	salt := <-in
	B := big.NewInt(0).SetBytes(<-in)
	uH := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
	u := big.NewInt(0).SetBytes(uH[:])
	//good to here
	salted := append(salt, []byte(password)...)
	xH := sha256.Sum256(salted)
	x := big.NewInt(0).SetBytes(xH[:])

	t0 := big.NewInt(0).Exp(g, x, p) //g**x %p
	t0 = t0.Mul(t0, k)
	t1 := big.NewInt(0).Sub(B, t0)
	t2 := big.NewInt(0).Add(a, big.NewInt(0).Mul(u, x))
	S := big.NewInt(0).Exp(t1, t2, p)

	K := sha256.Sum256(S.Bytes())

	hmacHasher := hmac.New(sha256.New, K[:])

	hm := hmacHasher.Sum(salt)

	out <- hm

	response := <-in
	return response

}

func main() {
	//usually need these
	rand.Seed(time.Now().Unix())
	cToS := make(chan []byte)
	sToC := make(chan []byte)
	go SRPServer(cToS, sToC)
	response := SRPClient(sToC, cToS)
	fmt.Println(string(response))

}
