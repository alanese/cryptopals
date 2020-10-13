package main

import (
	"bytes"
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
