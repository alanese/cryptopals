package main

import (
	"fmt"
	"math/rand"
	"time"
)

//IncrementPrintableBytes replaces b with the next slice of bytes
//(lexicographically) composed entirely of printable bytes.
func IncrementPrintableBytes(b []byte) {
	i := len(b) - 1
	for i >= 0 {
		b[i]++
		if b[i] > 126 {
			b[i] = 32
			i--
		} else {
			break
		}
	}
}

//AllBytesPrintable checks whether all bytes in the slice
//are in the ASCII printable range (0x20-0x7E)
func AllBytesPrintable(b []byte) bool {
	for _, v := range b {
		if v < 0x20 || v > 0x7E {
			return false
		}
	}
	return true
}

//C50ForgeMsg solves challenge 50. Creating a new string with the
//same CBC-MAC as the given and with a chosen prefix is fairly simple;
//the bulk of the code is devoted to finding such a string
//which is valid JavaScript.
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

func main() {
	rand.Seed(time.Now().Unix())
	C50ForgeMsg()
}
