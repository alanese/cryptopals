package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
)

//MysteryEncrypt sticks given plaintext on the front
//of some MYSTERY TEXT, pads it with PKCS#7,
//and encrypts with AES-ECB
func MysteryEncrypt(ptext []byte, key []byte) []byte {
	mysteryPtext := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	mysteryBytes, _ := base64.StdEncoding.DecodeString(mysteryPtext)
	newPtext := append(ptext, mysteryBytes...)
	newPtext = PKCSPad(newPtext, 16)
	return EncryptAESECB(newPtext, key)

}

//MysteryEncryptHard wraps MysteryEncrypt to add padding
//to the front of the plaintext before encryption
func MysteryEncryptHard(initialPad, ptext, key []byte) []byte {
	return MysteryEncrypt(append(initialPad, ptext...), key)
}

//BreakMysteryEncrypt uncovers the MYSTERY TEXT from MysteryEncrypt
func BreakMysteryEncrypt(mysteryKey []byte) []byte {
	mysteryLength := len(MysteryEncrypt([]byte{}, mysteryKey))
	as := []byte("A")
	for {
		ctext := MysteryEncrypt(as, mysteryKey)
		if DetectAESECB(ctext) {
			break
		}
		as = append(as, byte('A'))
	}

	blockSize := len(as) / 2
	knownBytes := []byte{}
	for i := 0; i < blockSize-1; i++ {
		knownBytes = append(knownBytes, byte('A'))
	}
	for i := 0; i < mysteryLength; i++ {
		currentBlock := i / blockSize
		byteInBlock := i % blockSize

		targetHead := knownBytes[byteInBlock : blockSize-1]
		targetCText := MysteryEncrypt(targetHead, mysteryKey)

		for j := 0; j < 256; j++ {
			testHead := append(knownBytes[byteInBlock:], byte(j))
			testCText := MysteryEncrypt(testHead, mysteryKey)
			if bytes.Equal(targetCText[currentBlock*blockSize:(currentBlock+1)*blockSize],
				testCText[currentBlock*blockSize:(currentBlock+1)*blockSize]) {
				knownBytes = append(knownBytes, byte(j))
				break
			}
		}
	}
	return knownBytes[blockSize-1:]
}

//BreakMysteryEncryptHard uncovers MYSTERY TEXT added
//by MysteryEncryptHard. Assumes the secret padding is
//at most 16 bytes. (It only uses the padding and key for encryption;
//they're in here as parameters so I don't have to hard-code them
//into MysteryEncrypt)
func BreakMysteryEncryptHard(secretPadding, key []byte) []byte {
	pad := []byte{}
	encryptNothing := MysteryEncryptHard(secretPadding, pad, key)
	prevFirstBlock := encryptNothing[:16]
	for {
		pad = append(pad, byte(0))
		firstBlock := MysteryEncryptHard(secretPadding, pad, key)[:16]
		if bytes.Equal(prevFirstBlock, firstBlock) {
			break
		}
		prevFirstBlock = firstBlock
	}
	pad = pad[:len(pad)-1]
	padLength := len(pad)
	//secretPadding + pad now is the length of a block
	secretPadLen := 16 - len(pad)
	mysteryLength := len(encryptNothing) - secretPadLen
	for i := 0; i < 15; i++ {
		pad = append(pad, byte(0))
	}
	for i := 0; i < mysteryLength; i++ {
		currentBlock := i/16 + 1
		byteInBlock := i % 16

		targetHead := pad[byteInBlock : padLength+15]
		targetCtext := MysteryEncryptHard(secretPadding, targetHead, key)

		for j := 0; j < 256; j++ {
			testHead := append(pad[byteInBlock:], byte(j))
			testCText := MysteryEncryptHard(secretPadding, testHead, key)
			if bytes.Equal(targetCtext[currentBlock*16:(currentBlock+1)*16],
				testCText[currentBlock*16:(currentBlock+1)*16]) {
				pad = append(pad, byte(j))
				//fmt.Println(string(pad[padLength+15:])) //Uncomment this line to see the text decrypted one byte at a time!
				break
			}
		}

	}
	return pad[padLength+15:]
}

//ParseKv parses something of the form k1=v1&k2=v2&k3=v3
//into a string-string map. Returns a non-nil error on a
//malformed input, or if regexp.MatchString returns one
func ParseKv(s string) (map[string]string, error) {
	validationRegex := "^([^&=]+=[^&=]+&)*[^&=]+=[^&=]+$"
	ok, err := regexp.MatchString(validationRegex, s)
	if !ok {
		return nil, errors.New("Malformed string")
	}
	if err != nil {
		return nil, err
	}

	pairs := strings.Split(s, "&")
	m := make(map[string]string)
	for _, p := range pairs {
		pair := strings.Split(p, "=")
		m[pair[0]] = pair[1]
	}
	return m, nil
}

//ProfileFor constructs a profile as per cryptopals challenge 13
func ProfileFor(email string) string {
	//strip encoding characters
	email = strings.ReplaceAll(email, "=", "")
	email = strings.ReplaceAll(email, "&", "")
	uid := fmt.Sprintf("%X", rand.Int())

	return "email=" + email + "&uid=" + uid + "&role=user"
}

//CreateEncryptedAdminProfile uses ProfileFor
//and EncryptProfile to construct a profile
//with the admin role. This will fail roughly
//1 in 8 attempts, due to potentially varying lengths
//of the uid. This requires EncryptProfile to run
//on a system where int is 32 bits. The encrypted text is
//padded with PKCS#7; assume an actual target system would
//expect that and compensate for it.
func CreateEncryptedAdminProfile(key []byte) []byte {
	sneakyBit := "admin" + string([]byte{11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11})
	sneakyEmail := "tom@exampl" + sneakyBit + "e.com"
	profile := ProfileFor(sneakyEmail)
	eProfile := EncryptProfile(profile, key)
	adminEnding := eProfile[16:32]
	regularEmail := "tom@example.com"
	regularEProfile := EncryptProfile(ProfileFor(regularEmail), key)
	adminStart := regularEProfile[:48]
	adminEProfile := append(adminStart, adminEnding...)
	return adminEProfile
}

//EncryptProfile encrypts the given profile string using AES-ECB
func EncryptProfile(profile string, key []byte) []byte {
	pText := PKCSPad([]byte(profile), 16)
	return EncryptAESECB(pText, key)
}

//DecryptParseProfile decrypts and parses a profile encrypted
//with AES-ECB
func DecryptParseProfile(ctext, key []byte) (map[string]string, error) {
	pText := string(DecryptAESECB(ctext, key))
	return ParseKv(pText)
}

//Challenge16Func generates, pads, and encrypts a
//data string as per challenge 16
func Challenge16Func(userdata string, secretKey, iv []byte) []byte {
	front := []byte("comment1=cooking%20MCs;userdata=")
	back := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	userdata = strings.ReplaceAll(userdata, "=", "%3D")
	userdata = strings.ReplaceAll(userdata, ";", "%3B")
	ptext := append(front, []byte(userdata)...)
	ptext = append(ptext, back...)
	ptext = PKCSPad(ptext, 16)
	return EncryptAESCBC(ptext, secretKey, iv)
}

//Challenge16AdminCheck decrypts a byte slice
//and checks whether it contains the text ";admin=true;"
func Challenge16AdminCheck(data []byte, secretkey, iv []byte) bool {
	ptext := DecryptAESCBC(data, secretkey, iv)
	ptext, _ = StripPKCS7Padding(ptext, 16)
	return bytes.Contains(ptext, []byte(";admin=true;"))
}

//Challenge16ForgeData creates a byte slice in the format
//output by Challenge16Func which, when decrypted, contains
//the text ";admin=true;" using a CBC bit-flipping attack
func Challenge16ForgeData(key, iv []byte) []byte {
	userdata := "aaaaaaaaaaaaaaaa"
	ctext := Challenge16Func(userdata, key, iv)
	uBytes := []byte(userdata)
	targetText := []byte("aaaaa;admin=true")
	flipper, _ := XorBufs(uBytes, targetText)
	sneakyText := ctext[:16]
	newBlock, _ := XorBufs(flipper, ctext[16:32])
	sneakyText = append(sneakyText, newBlock...)
	sneakyText = append(sneakyText, ctext[32:]...)
	return sneakyText
}
