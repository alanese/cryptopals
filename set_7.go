package main

import (
	"fmt"
	"math/rand"
	"strconv"
)

//C49ForgeMessage forges a message transmitting
//1M spacebucks from the original sender to account 563,
//given a message transmitting 1M spacebucks from the original
//sender to any account. Assumes account IDs are three digits.
func C49ForgeMessage(origMessage, origIV []byte) ([]byte, []byte) {
	newBlock := make([]byte, 16)
	newIV := make([]byte, 16)
	copy(newBlock, origMessage)
	copy(newIV, origIV)

	myAcct := []byte("563")
	origTo := origMessage[12:15]
	flipper, _ := XorBufs(myAcct, origTo)

	newIvChunk, _ := XorBufs(flipper, origIV[12:15])
	newIV[12] = newIvChunk[0]
	newIV[13] = newIvChunk[1]
	newIV[14] = newIvChunk[2]

	newBlock[12] = byte('5')
	newBlock[13] = byte('6')
	newBlock[14] = byte('3')
	return append(newBlock, origMessage[16:]...), newIV

}

//C50ForgeMsg solves challenge 50. Creating a new string with the
//same CBC-MAC as the given and with a chosen prefix is fairly simple;
//the bulk of the code is devoted to finding such a string
//which is valid JavaScript. (Roughly one in ten million
//16-byte blocks contain solely printable ASCII bytes, which is
//a sufficient condition for my purposes)
func C50ForgeMsg() []byte {
	origMsg := []byte("alert('MZA who was that?');\n")
	iv := make([]byte, 16)
	key := []byte("YELLOW SUBMARINE")
	mac := AESCBCMAC(origMsg, iv, key)
	fmt.Printf("%X\n", mac)

	var newMessage []byte
	origFirstBlock := origMsg[:16]
	origRemainder := origMsg[16:]
	newMsgFront := []byte("alert('Ayo, the Wu is back!');//")
	rPad := []byte("                ")
	for {
		fmt.Printf("Testing %X\n", rPad)
		testMsg := append(newMsgFront, rPad...)
		testMAC, _ := AESCBCMACNoPad(testMsg, iv, key)
		mangledBlock, _ := XorBufs(origFirstBlock, testMAC)
		if AllBytesPrintable(mangledBlock) {
			newMessage = append(newMsgFront, rPad...)
			newMessage = append(newMessage, mangledBlock...)
			newMessage = append(newMessage, origRemainder...)
			break
		}
		IncrementPrintableBytes(rPad)
	}

	newMAC := AESCBCMAC(newMessage, iv, key)
	fmt.Printf("%X\n", newMAC)
	fmt.Println(string(newMessage))
	return newMessage
}

//C51FormatRequest formats a request per challenge 51
func C51FormatRequest(p []byte) []byte {
	return []byte("POST / HTTP/1.1\n" +
		"Host: hapless.com\n" +
		"Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n" +
		"Content-length: " + strconv.Itoa(len(p)) + "\n" +
		string(p))
}

//C51OracleStream implements the compression oracle in challenge 51
//Encrypts with a MT19937 stream cipher because it's a stream
//cipher i have implemented
func C51OracleStream(p []byte) int {
	key := rand.Uint32()
	rq := C51FormatRequest(p)
	compressed := CompressDEFLATE(rq)
	encrypted := EncryptMT19937Stream(compressed, key)
	return len(encrypted)
}

//C51OracleCBC implements a CBC version of the compression
//oracle in challenge 51
func C51OracleCBC(p []byte) int {
	key := GenerateRandomByteSlice(16)
	iv := GenerateRandomByteSlice(16)
	rq := C51FormatRequest(p)
	compressed := CompressDEFLATE(rq)
	padded := PKCSPad(compressed, 16)
	encrypted := EncryptAESCBC(padded, key, iv)
	return len(encrypted)
}

//C51FindCookie uses a compression ratio attack to find
//a secret cookie in a request compressed with DEFLATE
//and encrypted with a stream cipher (MT19937, in this case)
func C51FindCookie() []byte {
	base64Bytes := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n")
	knownBytes := []byte("sessionid=")
	for {
		bestLength := 0
		bestByte := byte(0)
		for i := 0; i < len(base64Bytes); i++ {
			testBytes := append(knownBytes, base64Bytes[i])
			for j := 0; j < 3; j++ {
				testBytes = append(testBytes, knownBytes...)
				testBytes = append(testBytes, base64Bytes[i])
			}

			testLen := C51OracleStream(testBytes)
			if testLen < bestLength || i == 0 {
				bestLength = testLen
				bestByte = base64Bytes[i]
			}
		}
		if bestByte == '\n' {
			return knownBytes
		}
		knownBytes = append(knownBytes, bestByte)
		fmt.Println(string(knownBytes))
	}
}
