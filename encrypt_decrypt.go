//This file contains assorted encryption and decryption functions

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
)

//BreakSingleByteXor attempts to decrypt a byte slice
//encrypted with single-byte XOR, given a target byte distribution
func BreakSingleByteXor(ctext []byte, targetDist [256]int) []byte {
	minScore := 100.0
	var bestPtext []byte
	var curPtext []byte
	var curScore float64
	for i := 0; i < 256; i++ {
		curPtext = XorEncrypt(ctext, []byte{byte(i)})
		curScore = ScoreText(curPtext, targetDist)
		if curScore < minScore {
			minScore = curScore
			bestPtext = curPtext
		}
	}

	return bestPtext
}

//BreakKnownLenRepeatedXor attempts to decrypt a byte slice
//encrypted with repeated-key XOR with a known key length,
//given a target byte distribution
func BreakKnownLenRepeatedXor(ctext []byte, keyLen int, targetDist [256]int) []byte {
	blocks := make([][]byte, keyLen)
	for i := range blocks {
		tmp := EveryNth(ctext, i, keyLen)
		blocks[i] = BreakSingleByteXor(tmp, targetDist)
	}
	plainText := make([]byte, len(ctext))
	for i := range plainText {
		plainText[i] = blocks[i%keyLen][i/keyLen]
	}
	return plainText
}

//BreakRepeatedXor attempts to decrypt a byte slice
//encrypted with repeated-key XOR with unknown key length,
//given a target byte distribution. Assumes the key length is
//between 2 and 64 bytes inclusive.
func BreakRepeatedXor(ctext []byte, targetDist [256]int) []byte {
	keyLen := GuessRepeatedXorKeyLen(ctext, 2, 64)
	return BreakKnownLenRepeatedXor(ctext, keyLen, targetDist)
}

//DecryptAESCBC decrypts a byte slice using
//the built-in implementations of AES and CBC
func DecryptAESCBC(ctext []byte, key []byte, iv []byte) []byte {
	tmpC, _ := aes.NewCipher(key)
	c := cipher.NewCBCDecrypter(tmpC, iv)
	plainText := make([]byte, len(ctext))
	c.CryptBlocks(plainText, ctext)
	return plainText
}

//DecryptAESECB decrypts a ciphertext encrypted with AES-ECB
func DecryptAESECB(ctext []byte, key []byte) []byte {
	c, _ := aes.NewCipher(key)
	plainText := bytes.NewBuffer([]byte{})
	tmp := make([]byte, 16)
	for len(ctext) > 0 {
		c.Decrypt(tmp, ctext)
		plainText.Write(tmp)
		ctext = ctext[16:]
	}
	return plainText.Bytes()
}

//EncryptAESCBC encrypts a byte slice using
//the built-in implementations of AES and CBC
func EncryptAESCBC(ptext, key, iv []byte) []byte {
	tmpC, _ := aes.NewCipher(key)
	c := cipher.NewCBCEncrypter(tmpC, iv)
	cText := make([]byte, len(ptext))
	c.CryptBlocks(cText, ptext)
	return cText
}

//EncryptAESECB encrypts a ciphertext with AES-ECB
func EncryptAESECB(ptext []byte, key []byte) []byte {
	keyLength := len(key)
	cipher, _ := aes.NewCipher(key)
	cipherText := bytes.NewBuffer([]byte{})
	tmp := make([]byte, keyLength)
	for len(ptext) > 0 {
		cipher.Encrypt(tmp, ptext)
		cipherText.Write(tmp)
		ptext = ptext[keyLength:]
	}
	return cipherText.Bytes()
}

//EncryptAESCTRBlock encrypts a single 16-byte block of text using AES-CTR
//blockNum is the zero-indexed number of the block in the stream (i.e. 3 to
//use the fourth block in the keystream)
func EncryptAESCTRBlock(ptext, key, nonce []byte, blockNum int) []byte {
	keyBlock := GenerateCTRKeystreamBlock(key, nonce, LittleEndianCounter(blockNum))
	c, _ := XorBufs(keyBlock, ptext)
	return c
}

//EncryptAESCTR encrypts a given plaintext using AES-CTR with the given key
//and fixed nonce. Uses LittleEndianCounter as the counter function.
func EncryptAESCTR(ptext, key, nonce []byte) []byte {
	ctext := make([]byte, 0, len(ptext))
	for i := 0; i*16 < len(ptext); i++ {
		ptextBlock := ptext[16*i : 16*(i+1)]
		ctextBlock := EncryptAESCTRBlock(ptextBlock, key, nonce, i)
		ctext = append(ctext, ctextBlock...)
	}

	return ctext
}

//EncryptMT19937Stream encrypts the given bytes using
//a mersenne twister seeded with the key as a keystream
//The bytes of each uint32 value drawn from the twister
//are used beginning with the least significant.
func EncryptMT19937Stream(ptext []byte, key uint32) []byte {
	t := NewTwister(key)
	ctext := make([]byte, len(ptext))
	bitmask := uint32(0x000000FF)
	nextKeyChunk := uint32(0)
	for i, b := range ptext {
		byteInChunk := i % 4
		if byteInChunk == 0 {
			nextKeyChunk = t.Next()
		}

		keyByte := byte((nextKeyChunk >> (8 * byteInChunk)) & bitmask)
		ctext[i] = b ^ keyByte

	}

	return ctext
}

//EncryptRC4 encrypts the given plaintext under RC4
//with the given key
func EncryptRC4(ptext, key []byte) []byte {
	c, _ := rc4.NewCipher(key)
	ctext := make([]byte, len(ptext))
	c.XORKeyStream(ctext, ptext)
	return ctext
}

//XorEncrypt encrypts a plaintext byte slice with repeating-key XOR
func XorEncrypt(plaintext, key []byte) []byte {
	ct := make([]byte, len(plaintext))
	keyLength := len(key)
	for i, v := range plaintext {
		ct[i] = v ^ (key[i%keyLength])
	}
	return ct
}
