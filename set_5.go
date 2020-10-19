package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"time"
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

//GenerateDHPublicKey generates a diffie-hellman public
//key from the given private key, prime, and generator
func GenerateDHPublicKey(a, p, g *big.Int) *big.Int {
	return ModExp(g, a, p)
}

//GenerateNISTDHPublicKey1536 generates a Diffie-Hellman
//public key A from a private key a using the 1536-bit
//MODP group defined in RFC-3526 section 2
func GenerateNISTDHPublicKey1536(a *big.Int) *big.Int {
	p := big.NewInt(0)
	p.SetString(groupSizeString, 16)

	g := big.NewInt(2)
	return GenerateDHPublicKey(a, p, g)
}

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
	q, _ := big.NewInt(0).SetString(groupSizeString, 16)

	return GenerateDHPrivateKey(rnd, q)
}

//DiffieHellmanKeys generates two 128-bit keys using
//the receiver's public key A, the sender's private key b,
//and the chosen prime p
func DiffieHellmanKeys(A, b, p *big.Int) ([]byte, []byte) {
	sharedSecret := ModExp(A, b, p)
	secretHash := sha256.Sum256(sharedSecret.Bytes())
	return secretHash[:16], secretHash[16:]
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
