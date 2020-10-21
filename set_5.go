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

//DHEchoBob implements an "echo" bot. To use:
//Start as a goroutine, then send the chosen prime, the chosen generator, and
//Alice's public key over in. Read Bob's public key from out.
//Send a message encrypted with AES-CBC with the IV appended to the end over in
//Read the echoed message, encrypted similarly, from out.
//Close in to terminate the conversation - this will cause Bob to close out
//and end
func DHEchoBob(in, out chan []byte) {
	rSource := rand.New(rand.NewSource(time.Now().UnixNano()))
	pBytes := <-in
	p := big.NewInt(0).SetBytes(pBytes)
	gBytes := <-in
	g := big.NewInt(0).SetBytes(gBytes)
	b := GenerateDHPrivateKey(rSource, p)
	B := GenerateDHPublicKey(b, p, g)
	aBytes := <-in
	A := big.NewInt(0)
	A.SetBytes(aBytes)
	out <- B.Bytes()
	key1, _ := NISTDiffieHellmanKeys(A, b)
	for {
		v, ok := <-in
		if !ok {
			close(out)
			break
		}
		iv := v[len(v)-16:]
		aMsgEncrypted := v[:len(v)-16]
		aMsg := DecryptAESCBC(aMsgEncrypted, key1, iv)
		aMsg, _ = StripPKCS7Padding(aMsg, 16)
		fmt.Printf("BOB: Decrypted message from Alice: %v\n", string(aMsg))
		bobIv := GenerateRandomByteSlice(16)
		aMsg = PKCSPad(aMsg, 16)
		bMsgEncrypted := EncryptAESCBC(aMsg, key1, bobIv)
		bMsgEncrypted = append(bMsgEncrypted, bobIv...)
		out <- bMsgEncrypted

	}
}

//C34Mallory implements a MITM attack on Diffie-Hellman key exchange.
//Alice must initiate the key exchange, but once it is complete either
//Alice or Bob can send a message; Mallory will read the message and pass it on
//to the other party.  Run as a goroutine. Close either in channel to close both
//out channels and terminate.
func C34Mallory(aliceIn, aliceOut, bobIn, bobOut chan []byte) {
	pBytes := <-aliceIn
	gBytes := <-aliceIn
	_ = <-aliceIn
	bobOut <- pBytes
	bobOut <- gBytes
	bobOut <- pBytes
	_ = <-bobIn
	aliceOut <- pBytes
	sharedSecret := big.NewInt(0)
	secretHash := sha256.Sum256(sharedSecret.Bytes())
	key := secretHash[:16]

	for {
		select {
		case aliceMsg, ok := <-aliceIn:
			if !ok {
				close(aliceOut)
				close(bobOut)
				return
			}
			iv := aliceMsg[len(aliceMsg)-16:]
			encrypted := aliceMsg[:len(aliceMsg)-16]
			decrypted := DecryptAESCBC(encrypted, key, iv)
			decrypted, _ = StripPKCS7Padding(decrypted, 16)
			fmt.Printf("MALLORY: Intercepted message from Alice to Bob: %v\n", string(decrypted))
			bobOut <- aliceMsg
		case bobMsg, ok := <-bobIn:
			if !ok {
				close(aliceOut)
				close(bobOut)
				return
			}
			iv := bobMsg[len(bobMsg)-16:]
			decrypted := DecryptAESCBC(bobMsg[:len(bobMsg)-16], key, iv)
			decrypted, _ = StripPKCS7Padding(decrypted, 16)
			fmt.Printf("MALLORY: Intercepted message from Bob to Alice: %v\n", string(decrypted))
			aliceOut <- bobMsg

		}
	}

}

//C35EchoBob implements an echo bot with group negotiation
//per challenge 35
func C35EchoBob(in, out chan []byte) {
	p := big.NewInt(0).SetBytes(<-in)
	g := big.NewInt(0).SetBytes(<-in)
	out <- p.Bytes()
	out <- g.Bytes()
	b := GenerateDHPrivateKey(rand.New(rand.NewSource(time.Now().UnixNano())), p)
	B := GenerateDHPublicKey(b, p, g)
	A := big.NewInt(0).SetBytes(<-in)
	out <- B.Bytes()
	key, _ := DiffieHellmanKeys(A, b, p)

	for {
		msg, ok := <-in
		if !ok {
			close(out)
			break
		}
		iv := msg[len(msg)-16:]
		encryptedMsg := msg[:len(msg)-16]
		decrypted := DecryptAESCBC(encryptedMsg, key, iv)
		decrypted, _ = StripPKCS7Padding(decrypted, 16)
		fmt.Printf("BOB: Received message from Alice: %v\n", string(decrypted))

		echoMsg := PKCSPad(decrypted, 16)
		newIv := GenerateRandomByteSlice(16)
		encryptedEcho := EncryptAESCBC(echoMsg, key, newIv)
		encryptedEcho = append(encryptedEcho, newIv...)
		out <- encryptedEcho
	}

}

//C35Mallory implements a MITM attack on negotiated-group finite-field
//Diffie-Hellman with a malicious g parameter. Run as a go-routine
func C35Mallory(aliceIn, aliceOut, bobIn, bobOut chan []byte) {
	p := big.NewInt(0).SetBytes(<-aliceIn)
	<-aliceIn
	//Choose one of the following two lines:
	//g := big.NewInt(1)	//inject g=1
	g := big.NewInt(0).SetBytes(p.Bytes()) //inject g=p
	bobOut <- p.Bytes()
	bobOut <- g.Bytes() //inject malicious g
	tmp := <-bobIn
	aliceOut <- tmp
	tmp = <-bobIn
	aliceOut <- tmp

	A := <-aliceIn
	bobOut <- A
	B := <-bobIn
	aliceOut <- B
	key, _ := DiffieHellmanKeys(g, p, p)
	for {
		select {
		case v, ok := <-aliceIn:
			if !ok {
				close(aliceOut)
				close(bobOut)
				return
			}
			iv := v[len(v)-16:]
			msg := v[:len(v)-16]
			decrypted := DecryptAESCBC(msg, key, iv)
			decrypted, _ = StripPKCS7Padding(decrypted, 16)
			fmt.Printf("MALLORY: Intercepted message from Alice to Bob: %v\n", string(decrypted))
			bobOut <- v

		case v, ok := <-bobIn:
			if !ok {
				close(aliceOut)
				close(bobOut)
				return
			}
			iv := v[len(v)-16:]
			msg := v[:len(v)-16]
			decrypted := DecryptAESCBC(msg, key, iv)
			decrypted, _ = StripPKCS7Padding(decrypted, 16)
			fmt.Printf("MALLORY: Intercepted message from Bob to Alice: %v\n", string(decrypted))
			aliceOut <- v
		}
	}

}

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

//C38Server implements a simplified SRP server per challenge 38
func C38Server(in, out chan []byte) {
	password := "secret"
	g := big.NewInt(2)
	p, _ := big.NewInt(0).SetString(NIST1536GroupSize, 16)
	salt := GenerateRandomByteSlice(16)
	salted := append(salt, password...)
	xH := sha256.Sum256(salted)
	x := big.NewInt(0).SetBytes(xH[:])
	v := big.NewInt(0).Exp(g, x, p)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := GenerateNISTDHPrivateKey1536(rnd)
	B := big.NewInt(0).Exp(g, b, p)

	<-in //ignore username for this simple implementation
	A := big.NewInt(0).SetBytes(<-in)

	out <- salt
	out <- B.Bytes()
	uH := GenerateRandomByteSlice(16)
	out <- uH
	u := big.NewInt(0).SetBytes(uH)

	S := big.NewInt(0).Exp(v, u, p)
	S.Mul(S, A)
	S.Exp(S, b, p)
	K := sha256.Sum256(S.Bytes())

	hasher := hmac.New(sha256.New, K[:])
	trueHmac := hasher.Sum(salt)

	validateHmac := <-in

	if hmac.Equal(validateHmac, trueHmac) {
		out <- []byte("OK")
	} else {
		out <- []byte("ERROR")
	}

}

//C38Client implements a simplified SRP client per challenge 38
func C38Client(in, out chan []byte) bool {
	I := "bob"
	password := "pumbaa"
	p, _ := big.NewInt(0).SetString(NIST1536GroupSize, 16)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	a := GenerateNISTDHPrivateKey1536(rnd)
	A := GenerateNISTDHPublicKey1536(a)

	out <- []byte(I)
	out <- A.Bytes()

	salt := <-in
	B := big.NewInt(0).SetBytes(<-in)
	u := big.NewInt(0).SetBytes(<-in)

	salted := append(salt, password...)
	xH := sha256.Sum256(salted)
	x := big.NewInt(0).SetBytes(xH[:])
	exp := big.NewInt(0).Mul(u, x)
	exp.Add(a, exp)
	S := big.NewInt(0).Exp(B, exp, p)

	K := sha256.Sum256(S.Bytes())

	hasher := hmac.New(sha256.New, K[:])
	validateHmac := hasher.Sum(salt)
	out <- validateHmac

	resp := <-in

	return string(resp) == "OK"

}

//C38MITM cracks a simplified SRP password with a MITM attack.
//For simplicity, assumes the password is six lowercase letters
func C38MITM(in, out chan []byte) {
	p, _ := big.NewInt(0).SetString(NIST1536GroupSize, 16)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := GenerateNISTDHPrivateKey1536(rnd)
	B := GenerateNISTDHPublicKey1536(b)
	salt := GenerateRandomByteSlice(16)
	u := big.NewInt(0).SetBytes(GenerateRandomByteSlice(16))

	<-in //ignore username for this example
	A := big.NewInt(0).SetBytes(<-in)
	out <- salt
	out <- B.Bytes()
	out <- u.Bytes()

	targetHmac := <-in

	dhKey := big.NewInt(0).Exp(A, b, p)

	testPW := []byte{97, 97, 97, 97, 97, 97}
	for {
		fmt.Printf("Testing password %v\n", string(testPW))
		salted := append(salt, testPW...)
		xH := sha256.Sum256(salted)
		x := big.NewInt(0).SetBytes(xH[:])
		exp := big.NewInt(0).Mul(u, x)
		S := big.NewInt(0).Exp(B, exp, p)
		S.Mul(S, dhKey)
		S.Mod(S, p)
		K := sha256.Sum256(S.Bytes())
		hasher := hmac.New(sha256.New, K[:])
		testHmac := hasher.Sum(salt)
		if hmac.Equal(targetHmac, testHmac) {
			fmt.Printf("Found password: %v\n", string(testPW))
			out <- []byte("ERROR")
			return
		}
		testPW[0]++
		if testPW[0] > 122 {
			testPW[0] = 97
			testPW[1]++
			if testPW[1] > 122 {
				testPW[1] = 97
				testPW[2]++
				if testPW[2] > 122 {
					testPW[2] = 97
					testPW[3]++
					if testPW[3] > 122 {
						testPW[3] = 97
						testPW[4]++
						if testPW[4] > 122 {
							testPW[4] = 97
							testPW[5]++
							if testPW[5] > 122 {
								fmt.Printf("Failed to find password\n")
								out <- []byte("ERROR")
							}
						}
					}
				}
			}
		}

	}
}

//C40BreakRSA encrypts the given message three times using three
//randomly-generated RSA public keys, then breaks the encryption
func C40BreakRSA(msg []byte) {
	e1, _, n1 := GenerateRSAKeyPair(64)
	e2, _, n2 := GenerateRSAKeyPair(64)
	e3, _, n3 := GenerateRSAKeyPair(64)

	encrypted1 := big.NewInt(0).SetBytes(RSAEncrypt(msg, e1, n1))
	encrypted2 := big.NewInt(0).SetBytes(RSAEncrypt(msg, e2, n2))
	encrypted3 := big.NewInt(0).SetBytes(RSAEncrypt(msg, e3, n3))

	ms1 := big.NewInt(0).Mul(n2, n3)
	ms2 := big.NewInt(0).Mul(n1, n3)
	ms3 := big.NewInt(0).Mul(n1, n2)
	inv1 := big.NewInt(0).ModInverse(ms1, n1)
	inv2 := big.NewInt(0).ModInverse(ms2, n2)
	inv3 := big.NewInt(0).ModInverse(ms3, n3)

	res1 := big.NewInt(0).Mul(encrypted1, ms1)
	res1.Mul(res1, inv1)
	res2 := big.NewInt(0).Mul(encrypted2, ms2)
	res2.Mul(res2, inv2)
	res3 := big.NewInt(0).Mul(encrypted3, ms3)
	res3.Mul(res3, inv3)

	tot := big.NewInt(0).Add(res1, res2)
	tot.Add(tot, res3)

	totalMod := big.NewInt(0).Mul(n1, n2)
	totalMod.Mul(totalMod, n3)

	tot.Mod(tot, totalMod)

	decrypted := NRoot(tot, 3)

	decryptedH := decrypted.Bytes()

	fmt.Printf("Original bytes: %X\n", msg)
	fmt.Printf("Dcrypted bytes: %X\n", decryptedH) //Typo is intentional for alignment
	fmt.Printf("Original message %v\n", string(msg))
	fmt.Printf("Dcrypted message %v\n", string(decryptedH))

}
