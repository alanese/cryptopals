package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"
)

//Challenge17Encrypt randomly chooses one of 10 Base64-encoded
//strings, decodes it, pads it, and encrypts it with AES-CBC
//using the given key and IV
func Challenge17Encrypt(key, iv []byte) []byte {
	options := []string{"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"}
	pText, _ := base64.StdEncoding.DecodeString(options[rand.Intn(len(options))])
	pText = PKCSPad(pText, 16)
	return EncryptAESCBC(pText, key, iv)
}

//Challenge17Decrypt decrypts the given AES-CBC ciphertext
//with the given key and IV and returns a nil error if
//the plaintext is properly PKCS#7-padded, non-nil otherwise
func Challenge17Decrypt(ctext, key, iv []byte) error {
	ptext := DecryptAESCBC(ctext, key, iv)
	_, err := StripPKCS7Padding(ptext, 16)
	return err
}

//Challenge17GetPrevByte , given a ciphertext and a known suffix
//of the plaintext, finds the plaintext byte preceding the known
//suffix using a padding oracle attack.
func Challenge17GetPrevByte(cText, knownBytes, key, iv []byte) byte {
	testLength := len(knownBytes) + 1
	head := cText[0 : len(cText)-testLength-16]
	mid := cText[len(cText)-testLength-16 : len(cText)-16]
	tail := cText[len(cText)-16:]
	flipper := append([]byte{byte(0)}, knownBytes...)
	for i := 1; i < len(flipper); i++ {
		flipper[i] = flipper[i] ^ byte(testLength)
	}
	testCtext := bytes.NewBuffer([]byte{})
	for i := 0; i < 256; i++ {
		flipper[0] = byte(i)
		testMid, _ := XorBufs(mid, flipper)
		_, _ = testCtext.Write(head)
		_, _ = testCtext.Write(testMid)
		_, _ = testCtext.Write(tail)
		err := Challenge17Decrypt(testCtext.Bytes(), key, iv)
		if err == nil {
			if testLength > 1 {
				return byte(i) ^ byte(testLength)
			}
			testCtext.Reset()
			_, _ = testCtext.Write(head[:len(head)-1])
			_ = testCtext.WriteByte(head[len(head)-1] ^ byte(1))
			_, _ = testCtext.Write(testMid)
			_, _ = testCtext.Write(tail)
			err := Challenge17Decrypt(testCtext.Bytes(), key, iv)
			if err == nil {
				return byte(i) ^ byte(testLength)

			}
		}
		testCtext.Reset()

	}
	panic("Found no valid bytes")
}

//Challenge17GetLastBlock finds the last plaintext block
//of the given ciphertext using a CBC padding oracle attack
func Challenge17GetLastBlock(cText, key, iv []byte) []byte {
	knownBytes := []byte{}
	for i := 0; i < 16; i++ {
		nextByte := Challenge17GetPrevByte(cText, knownBytes, key, iv)
		knownBytes = append([]byte{nextByte}, knownBytes...)
	}
	return knownBytes
}

//Challenge18Decrypt decrypts the text from challenge 18.
func Challenge18Decrypt() {
	key := []byte("YELLOW SUBMARINE")
	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	cText, _ := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	keystream := GenerateCTRKeystream(6, key, nonce, LittleEndianCounter)
	keystream = keystream[:len(cText)]
	pText, _ := XorBufs(keystream, cText)
	fmt.Println(string(pText))

}

//Challenge20 breaks fixed-nonce CTR statistically as per challenge 20
func Challenge20(sourceFname, sampleFname string) {
	lines, _ := LinesFromFile(sourceFname)
	decodedLines := make([][]byte, len(lines)-1)
	minLength := 99999999
	for i, v := range lines[:len(lines)-1] {
		line, _ := base64.StdEncoding.DecodeString(string(v))
		decodedLines[i] = line
		if len(line) < minLength {
			minLength = len(line)
		}
	}
	truncatedLines := []byte{}
	for _, v := range decodedLines {
		truncatedLines = append(truncatedLines, v[:minLength]...)
	}

	targetFreq, _ := FileFreqCount(sampleFname)

	pText := BreakKnownLenRepeatedXor(truncatedLines, minLength, targetFreq)
	fmt.Println(string(pText))
}

//Challenge22RandomNum creates a new Twister seeded with the current time
//plus a random offset of 40 to 940 seconds. Returns the first random value
//from the twister, and the random seed (only used so I can see if I did
//the challenge correctly)
func Challenge22RandomNum() (uint32, uint32) {
	timeSeed := uint32(time.Now().Unix()) + uint32(rand.Intn(900)+40)
	t := NewTwister(uint32(timeSeed))
	return t.Next(), timeSeed
}

//Challenge22BreakSeed creates a new Mersenne Twister with
//a random seed near the current timestamp, then uses
//the twister's first output to deduce the seed.
//If Go's default random Source hasn't been seeded,
//the random seed will be the same every time.
func Challenge22BreakSeed() {
	rightNow := time.Now().Unix()
	target, secretSeed := Challenge22RandomNum()
	for i := rightNow - 30; i < rightNow+1000; i++ {
		testTwist := NewTwister(uint32(i))
		if testTwist.Next() == target {
			fmt.Printf("Guessed %X\nActual  %X\n", uint32(i), secretSeed)
			break
		}
	}
}

//C23UntemperRight11 inverts the tempering transformation
//y ^= (y>>11)
func C23UntemperRight11(x uint32) uint32 {
	top := x >> 21
	mid := ((x & 0x001FFC00) >> 10) ^ top
	bottom := (x & 0x000003FF) ^ (mid >> 1)
	return (top << 21) | (mid << 10) | bottom
}

//C23UntemperRight18 inverts the tempering transformation
//y ^= (y >> 18)
func C23UntemperRight18(x uint32) uint32 {
	top := x >> 14
	bottom := (x & 0x00003FFF) ^ (top >> 4)
	return (top << 14) | bottom
}

//C23UntemperLeft inverts the tempering transformation
//y ^= ((y << shift) & magicNum) for uint32's
func C23UntemperLeft(x, magicNum uint32, shift int) uint32 {
	chunks := []uint32{}
	bitmask := RightOnes(shift)
	tmp := x & bitmask
	chunks = append(chunks, tmp)
	x >>= shift
	magicNum >>= shift
	i := shift
	for i < 32 {
		tmp = (x ^ (chunks[len(chunks)-1] & magicNum)) & bitmask
		chunks = append(chunks, tmp)
		x >>= shift
		magicNum >>= shift
		i += shift
	}
	untempered := uint32(0)
	for i, v := range chunks {
		untempered |= (v << (i * shift))
	}
	return untempered
}

//TwisterUntemper inverts the tempering transformation
//used in the Mersenne twister
func TwisterUntemper(x uint32) uint32 {
	x = C23UntemperRight18(x)
	x = C23UntemperLeft(x, 0xEFC60000, 15)
	x = C23UntemperLeft(x, 0x9D2C5680, 7)
	x = C23UntemperRight11(x)
	return x
}

//CloneTwister creates a clone of the given twister.
//Assumes t.index is 0 or 624. Consumes 624 values from t.
func CloneTwister(t *Twister) *Twister {
	state := [624]uint32{}
	for i := range state {
		r := t.Next()
		state[i] = TwisterUntemper(r)
	}
	cloned := NewTwister(1)
	cloned.x = state
	return &cloned
}

//C24RecoverKey recovers a (16-bit) key used to encrypt
//a random prefix followed by a known plaintext
func C24RecoverKey(key uint32) uint32 {
	padLength := rand.Intn(5) + 5
	pad := GenerateRandomByteSlice(padLength)
	knownText := []byte("AAAAAAAAAAAAAA")
	pText := append(pad, knownText...)
	cText := EncryptMT19937Stream(pText, key)
	knownStart := len(pText) - len(knownText)

	testPtext := make([]byte, len(cText))
	for i := range testPtext {
		testPtext[i] = byte('A')
	}

	for i := 0; i < (1 << 16); i++ {
		testCtext := EncryptMT19937Stream(testPtext, uint32(i))
		if bytes.Equal(cText[knownStart:], testCtext[knownStart:]) {
			return uint32(i)
		}
	}

	return 0

}

//C24GenerateResetToken generates and encrypts a "reset token"
//using the given username. Encrypts using the MT19937 stream
//cipher seeded with the current unix timestamp
func C24GenerateResetToken(uname string) []byte {
	head := "reset_password?uname=" + uname
	tokenBytes := []byte(head)
	seed := uint32(time.Now().Unix())

	return EncryptMT19937Stream(tokenBytes, seed)
}

//C24ValidateToken checks whether the given bytes are a valid
//"reset token" as created by C24GenerateResetToken and encrypted
//with the current Unix timestamp
func C24ValidateToken(token []byte) bool {
	if len(token) < 21 {
		return false
	}
	seed := uint32(time.Now().Unix())
	decryptedToken := EncryptMT19937Stream(token, seed)
	testHead := []byte("reset_password?uname=")
	return bytes.Equal(testHead, decryptedToken[:21])

}
