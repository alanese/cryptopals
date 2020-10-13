package main

import (
	"bytes"
	"strings"
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
