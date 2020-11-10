package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"strconv"

	"golang.org/x/crypto/twofish"
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

//C52MD implements a simplified MD iterated hash using AES-ECB
//with a digest size of 16 bits
func C52MD(M, H []byte) []byte {
	key := PadLeft(H, 0x00, 16)
	msg := M
	for i := 0; i*16 < len(msg); i++ {
		longKey := EncryptAESECB(msg[16*i:16*(i+1)], key)
		key = PadLeft(longKey[14:], 0x00, 16)
	}
	return key[14:]
}

//C52TwofishMD implements a simplified MD iterated hash using
//Twofish with a digest size of 16 bits
func C52TwofishMD(M, H []byte) []byte {
	key := PadLeft(H, 0x00, 16)
	block := make([]byte, 16)
	copy(block, M[:16])
	for i := 0; i*16 < len(M); i++ {
		c, _ := twofish.NewCipher(key)
		c.Encrypt(block, M[i*16:(i+1)*16])
		key = PadLeft(block[14:], 0x00, 16)
	}
	return key[14:]
}

//C52GenerateCollision finds two 16-byte slices which produce the
//same hash under C52MD with the given initial state (which should be
//two bytes)
func C52GenerateCollision(initState []byte) ([]byte, []byte) {
	for {
		i1 := GenerateRandomByteSlice(16)
		i2 := GenerateRandomByteSlice(16)
		h1 := C52MD(i1, initState)
		h2 := C52MD(i2, initState)
		if bytes.Equal(h1, h2) {
			return i1, i2
		}
	}
}

//C52GenerateManyCollisions generates 2**n byte slices which all
//collide under C52MD with the given initial state.
func C52GenerateManyCollisions(initState []byte, n int) [][]byte {
	state := initState
	pairs := make([][][]byte, n)
	for i := 0; i < n; i++ {
		i1, i2 := C52GenerateCollision(state)
		state = C52MD(i1, state)
		pairs[i] = [][]byte{i1, i2}
	}
	fmt.Printf("%x\n", pairs)

	colliders := make([][]byte, 1<<n)
	for i := 0; i < 1<<n; i++ {
		tmp := make([]byte, 0)
		for j := 0; j < n; j++ {
			tmp = append(tmp, pairs[j][(i>>j)&1]...)
		}
		colliders[i] = tmp
	}
	return colliders
}
