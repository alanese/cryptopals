package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"time"
)

//SRPServer implements the server side of an SRP password
//verification scheme
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

//SRPClient implements the client side of an SRP password
//verification scheme
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

//C37LogIn implements the client side of an SRP password
//verification scheme running over a network
func C37LogIn(username, password string) bool {
	genbBase := "http://localhost:8080/getB?u=%v&A=%X"
	verifyBase := "http://localhost:8080/validate?u=%v&signature=%X"

	k := big.NewInt(3)
	g := big.NewInt(2)
	p, _ := big.NewInt(0).SetString(NIST1536GroupSize, 16)

	rSource := rand.New(rand.NewSource(time.Now().UnixNano()))

	a := GenerateNISTDHPrivateKey1536(rSource)
	A := GenerateNISTDHPublicKey1536(a)

	genbresp, _ := http.Get(fmt.Sprintf(genbBase, username, A))
	respLength := genbresp.ContentLength
	salt := make([]byte, 16)
	genbresp.Body.Read(salt)
	BBytes := make([]byte, respLength-16)
	genbresp.Body.Read(BBytes)
	B := big.NewInt(0).SetBytes(BBytes)

	uH := sha256.Sum256(append(A.Bytes(), BBytes...))
	u := big.NewInt(0).SetBytes(uH[:])

	salted := append(salt, password...)
	xH := sha256.Sum256(salted)
	x := big.NewInt(0).SetBytes(xH[:])

	t0 := big.NewInt(0).Exp(g, x, p)
	t0.Mul(t0, k)
	t0.Sub(B, t0)
	t1 := big.NewInt(0).Mul(u, x)
	t1.Add(t1, a)
	S := big.NewInt(0).Exp(t0, t1, p)
	K := sha256.Sum256(S.Bytes())

	hasher := hmac.New(sha256.New, K[:])

	verifyHmac := hasher.Sum(salt)

	verifyResp, _ := http.Get(fmt.Sprintf(verifyBase, username, verifyHmac))
	return verifyResp.StatusCode == http.StatusOK

}

//C37BypassLogIn fools an improperly-safeguarded SRP password
//verification scheme into granting access without knowing
//the password
func C37BypassLogIn(username string) bool {
	genbBase := "http://localhost:8080/getB?u=%v&A=%X"
	verifyBase := "http://localhost:8080/validate?u=%v&signature=%X"

	A := big.NewInt(0)
	genbresp, _ := http.Get(fmt.Sprintf(genbBase, username, A))
	salt := make([]byte, 16)
	genbresp.Body.Read(salt)

	K := sha256.Sum256(A.Bytes())
	hasher := hmac.New(sha256.New, K[:])

	verifyHmac := hasher.Sum(salt)
	verifyResp, _ := http.Get(fmt.Sprintf(verifyBase, username, verifyHmac))

	return verifyResp.StatusCode == http.StatusOK
}

func main() {

	//ok := C37LogIn("bob", "secretpassword123")
	ok := C37BypassLogIn("bob")
	fmt.Println(ok)

}
