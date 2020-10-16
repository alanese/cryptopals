package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

//C25Edit decrypts the ciphertext (using AES-CTR with the given key),
//truncates after offset bytes, adds newText, then re-encrypts.
func C25Edit(ctext, key, newtext []byte, offset int) []byte {
	nonce := make([]byte, 8)
	originalPtext := EncryptAESCTR(ctext, key, nonce)
	newPtext := bytes.NewBuffer([]byte{})
	newPtext.Write(originalPtext[:offset])
	newPtext.Write(newtext)
	newCtext := EncryptAESCTR(newPtext.Bytes(), key, nonce)
	return newCtext
}

//C25BreakEdit uses C25Edit to break an AES-CTR encrypted
//ciphertext via a chosen-plaintext attack.
func C25BreakEdit(ctext, key []byte) []byte {
	zeroes := make([]byte, len(ctext))
	keystream := C25Edit(ctext, key, zeroes, 0)
	ptext, _ := XorBufs(ctext, keystream)
	return ptext
}

//Challenge26Func generates, pads, and encrypts a
//data string as per challenge 26 (C16 reimplemented with CTR)
func Challenge26Func(userdata string, secretKey []byte) []byte {
	front := []byte("comment1=cooking%20MCs;userdata=")
	back := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	userdata = strings.ReplaceAll(userdata, "=", "%3D")
	userdata = strings.ReplaceAll(userdata, ";", "%3B")
	ptext := append(front, []byte(userdata)...)
	ptext = append(ptext, back...)
	ptext = PKCSPad(ptext, 16)
	nonce := make([]byte, 8) //use 0s as the nonce
	return EncryptAESCTR(ptext, secretKey, nonce)
}

//Challenge26AdminCheck decrypts a byte slice
//and checks whether it contains the text ";admin=true;"
//(C16 reimplemented with CTR)
func Challenge26AdminCheck(data []byte, secretkey []byte) bool {
	nonce := make([]byte, 8) //use 0s for nonce
	ptext := EncryptAESCTR(data, secretkey, nonce)
	ptext, _ = StripPKCS7Padding(ptext, 16)
	return bytes.Contains(ptext, []byte(";admin=true;"))
}

//Challenge26ForgeData creates a byte slice in the format
//output by Challenge16Func which, when decrypted, contains
//the text ";admin=true;" using a CTR bit-flipping attack
//(C16 reimplemented with CTR)
func Challenge26ForgeData(key []byte) []byte {
	userdata := "aaaaaaaaaaaaaaaa"
	ctext := Challenge26Func(userdata, key)
	uBytes := []byte(userdata)
	targetText := []byte("aaaaa;admin=true")
	flipper, _ := XorBufs(uBytes, targetText)
	sneakyText := ctext[:32]
	newBlock, _ := XorBufs(flipper, ctext[32:48])
	sneakyText = append(sneakyText, newBlock...)
	sneakyText = append(sneakyText, ctext[48:]...)
	return sneakyText
}

//Challenge27VerifyDecrypt attempts to decrypt the ciphertext using the key
//as the IV; it returns the decrypted plaintext and a non-nil error if the
//plaintext contains any non-ASCII bytes, and returns two nils otherwise
func Challenge27VerifyDecrypt(ctext, key []byte) ([]byte, error) {
	pText := DecryptAESCBC(ctext, key, key)
	for _, v := range pText {
		if v > 127 {
			return pText, errors.New("Invalid character")
		}
	}
	return nil, nil
}

//Challenge27ExtractKey uses Challenge27VerifyDecrypt to determine
//the secret key
func Challenge27ExtractKey(secretKey []byte) []byte {
	pText := make([]byte, 48)
	pText[0] = byte(128)
	cText := EncryptAESCBC(pText, secretKey, secretKey)
	newCText := bytes.NewBuffer(cText[:16])
	newCText.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	newCText.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) //write 16 zero bytes
	newCText.Write(cText[:16])
	extractedPtext, _ := Challenge27VerifyDecrypt(newCText.Bytes(), secretKey)
	p1 := extractedPtext[0:16]
	p3 := extractedPtext[32:48]
	extractedKey, _ := XorBufs(p1, p3)
	return extractedKey
}

//C29ValidateMAC tests whether the given digest is the SHA-1
//hash of key || message. An attacker exploiting this function
//doesn't actually know key; it's passed as a parameter so I don't
//have to maintain global variables.
func C29ValidateMAC(key, message, digest []byte) bool {
	testDigest := SHA1Hash(append(key, message...))
	return bytes.Equal(digest, testDigest)
}

//C29GluePadding generates the appropriate SHA-1 padding for
//a message of the given length
func C29GluePadding(length int) []byte {
	pad := make([]byte, 0)
	pad = append(pad, 0x80)
	for (length+len(pad))%64 != 56 {
		pad = append(pad, 0)
	}
	ml := uint64(length * 8)
	pad = append(pad, AsBytes64(ml)...)
	return pad
}

//C29ForgeMAC generates a message/digest pair that will be validated
//under a secret-prefix SHA-1 MAC. The generated message is the original
//message, plus some padding, plus the text ";admin=true"
//Assumes the length of the original message plus the secret key is
//from 64 to 119 bytes
func C29ForgeMAC(key, message, origDigest []byte) (forgedMsg, forgedHash []byte) {
	addedMsg := []byte(";admin=true")
	pad := C29GluePadding(139)
	paddedAddedMsg := append(addedMsg, pad...)
	h0 := FromBytes32(origDigest[0:4])
	h1 := FromBytes32(origDigest[4:8])
	h2 := FromBytes32(origDigest[8:12])
	h3 := FromBytes32(origDigest[12:16])
	h4 := FromBytes32(origDigest[16:20])
	targetHash := SHA1HashExtend(paddedAddedMsg, h0, h1, h2, h3, h4)

	msgBuffer := bytes.NewBuffer([]byte{})
	for i := 0; i < 33; i++ {
		msgBuffer.Write(message)
		msgBuffer.Write(C29GluePadding(len(message) + i))
		msgBuffer.Write(addedMsg)
		if C29ValidateMAC(key, msgBuffer.Bytes(), targetHash) {
			return msgBuffer.Bytes(), targetHash
		}
		msgBuffer.Reset()

	}
	return nil, nil
}

//C30GluePadding computes the padding bytes added
//to a message of given length in hashing with MD4
func C30GluePadding(length int) []byte {
	m := []byte{0x80}
	for (length+len(m))%64 != 56 {
		m = append(m, 0x00)
	}
	ml := AsBytes64(uint64(length * 8))

	//append bytes in little-endian order
	m = append(m, ml[7], ml[6], ml[5], ml[4], ml[3], ml[2], ml[1], ml[0])
	return m
}

//C30ValidateMAC checks if the digest is the MD4 hash
//of key || message
func C30ValidateMAC(key, message, digest []byte) bool {
	target := MD4Hash(append(key, message...))
	return bytes.Equal(target, digest)
}

//C30ForgeMAC forges a MAC/digest pair as per challenge 30
func C30ForgeMAC(key, message, origDigest []byte) (forgedMsg, forgedHash []byte) {
	addedMsg := []byte(";admin=true")
	secretMsg := append(key, message...)
	secretMsg = append(secretMsg, C30GluePadding(len(secretMsg))...)
	secretMsg = append(secretMsg, addedMsg...)
	targetHash := MD4Hash(secretMsg)

	msgBuffer := bytes.NewBuffer([]byte{})
	for i := 0; i < 15; i++ {
		msgBuffer.Write(message)
		msgBuffer.Write(C30GluePadding(len(message) + i))
		msgBuffer.Write(addedMsg)
		if C30ValidateMAC(key, msgBuffer.Bytes(), targetHash) {
			return msgBuffer.Bytes(), targetHash
		}
		msgBuffer.Reset()
	}
	return nil, nil
}

//InsecureCompare determines whether two byte slices
//contain the same elements with early exit, with an
//artificially-emphasized timing leak
func InsecureCompare(b1, b2 []byte) bool {
	if len(b1) != len(b2) {
		return false
	}
	for i := range b1 {
		if b1[i] != b2[i] {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}

	return true
}

//C31VerifyHMAC verifies that the secret-prefix HMAC of
//the file query parameter equals the signature parameter
func C31VerifyHMAC(rw http.ResponseWriter, rq *http.Request) {
	secret := []byte("THIS IS A SECRET DON'T TELL ANYONE")
	file := []byte(rq.URL.Query().Get("file"))
	hmac, _ := hex.DecodeString(rq.URL.Query().Get("signature"))
	hmac = PadLeft(hmac, 0, 20)
	fileHmac := HMACSHA1(secret, file)
	if InsecureCompare(fileHmac, hmac) {
		rw.Write([]byte("OK"))
	} else {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Invalid hash"))
	}
}

//C31GetOverheadMS sends intentionally bad HMAC
//verification requests to determine the time taken in milliseconds
//by non-comparison parts of verification (e.g. network travel times)
func C31GetOverheadMS(urlFormat string) int {
	attempts := 5
	fakeHmac := make([]byte, 20)
	testURL := fmt.Sprintf(urlFormat, "a", fakeHmac)

	overheadSum0 := 0
	for i := 0; i < attempts; i++ {
		t, r, _ := TimedGet(testURL)
		overheadSum0 += t
		r.Body.Close()
	}

	fakeHmac[0] = 0x01
	testURL = fmt.Sprintf(urlFormat, "a", fakeHmac)
	overheadSum1 := 0
	for i := 0; i < attempts; i++ {
		t, r, _ := TimedGet(testURL)
		overheadSum1 += t
		r.Body.Close()
	}

	if overheadSum0 > overheadSum1 {
		return overheadSum1 / attempts
	}
	return overheadSum0 / attempts

}

//C31GetByteDelay estimates the per-byte compare time
//for the insecure comparison in challenges 31/32
func C31GetByteDelay(urlformat string, overhead int, verbose bool) int {
	attemptsPerValue := 5
	testHmac := make([]byte, 20)

	maxTime := 0

	for i := 0; i < 256; i++ {
		if verbose {
			fmt.Printf("Delay testing: 0x%02X\n", i)
		}
		totalTime := 0
		testHmac[0] = byte(i)
		testURL := fmt.Sprintf(urlformat, "a", testHmac)
		for j := 0; j < attemptsPerValue; j++ {
			t, r, _ := TimedGet(testURL)
			r.Body.Close()
			totalTime += (t - overhead)
		}
		if totalTime > maxTime {
			maxTime = totalTime
		}
	}
	return maxTime / attemptsPerValue
}

//C31BreakHash finds the HMAC-SHA1 signature for the given message
//expected by a server. urlBase should be a printf-style format string
//with %v for the message and %X for the signature. The server should
//return a 200 OK response if the signature is valid and a 500 error response if not.
//Tested with a server running on localhost with an artificial delay of 2 ms per byte
//compared. The verbose parameter determines whether status messages are printed to console.
//Panics if the server returns any response other than a 200 OK or a 500
func C31BreakHash(urlBase, msg string, verbose bool) []byte {
	hmac := make([]byte, 20)
	overheadMs := C31GetOverheadMS(urlBase)
	if verbose {
		fmt.Printf("Overhead %v ms\n", overheadMs)
	}
	byteDelay := C31GetByteDelay(urlBase, overheadMs, verbose)
	if verbose {
		fmt.Printf("Estimated byte delay %v ms\n", byteDelay)
	}
	i := 0
	for {
		hmac[i]++
		queryURL := fmt.Sprintf(urlBase, msg, hmac)
		if verbose {
			fmt.Printf("Testing hash %X\n", hmac)
		}
		msDelay, r, _ := TimedGet(queryURL)
		if r.StatusCode == http.StatusOK {
			return hmac
		}
		if r.StatusCode != http.StatusInternalServerError {
			panic("Unnexpected Http status " + r.Status)
		}

		msDelay -= overheadMs
		delayBlocks := msDelay / byteDelay

		if verbose {
			fmt.Printf("%v ms delay, %v bytes likely correct\n", msDelay, delayBlocks)
		}

		i = delayBlocks
		if i >= len(hmac) {
			i = len(hmac) - 1
		}
	}
}
