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

//C53GenerateCollisionPair generates a one-block message and a message of the given
//length in blocks which collide under C52 with the given initial state
func C53GenerateCollisionPair(initState []byte, longBlocks int) ([]byte, []byte) {
	longMsg := GenerateRandomByteSlice(longBlocks * 16)
	longHash := C52MD(longMsg, initState)
	for {
		shortMsg := GenerateRandomByteSlice(16)
		shortHash := C52MD(shortMsg, initState)
		if bytes.Equal(shortHash, longHash) {
			return shortMsg, longMsg
		}
	}
}

//C53GenerateExpandableMessage generates collisions under C52MD for use
//in an expandable-message attack
func C53GenerateExpandableMessage(initState []byte, k int) (shortMsgs, longMsgs [][]byte, state []byte) {
	state = initState
	shortMsgs = make([][]byte, k)
	longMsgs = make([][]byte, k)
	for i := 0; i < k; i++ {
		short, long := C53GenerateCollisionPair(state, (1<<(k-i-1))+1)
		shortMsgs[i] = short
		longMsgs[i] = long
		state = C52MD(short, state)
	}
	return

}

//C53ForgeMessage forges a message of the appropriate length whose
//hash (under the simplified MD hash in C52MD) matches that of the
//given message. 2**k should be the length of the message in blocks
func C53ForgeMessage(msg, initState []byte, k int) []byte {
	intermediateStates := make(map[string]int)
	state := initState
	for i := 0; i*16 < len(msg); i++ {
		state = C52MD(msg[i*16:(i+1)*16], state)
		intermediateStates[fmt.Sprintf("%x", state)] = i + 1
	}

	shortMsgs, longMsgs, expandableState := C53GenerateExpandableMessage(initState, k)
	var bridge []byte
	var bridgeIndex int
	ok := false
	for !ok || bridgeIndex < k {
		bridge = GenerateRandomByteSlice(16)
		bridgeState := C52MD(bridge, expandableState)
		bridgeIndex, ok = intermediateStates[fmt.Sprintf("%x", bridgeState)]
	}

	msgTail := append(bridge, msg[16*bridgeIndex:]...)
	msgHead := make([]byte, 0)
	prefixLength := len(msg) - len(msgTail)

	prefixBuilder := (prefixLength / 16) - k
	for i := 0; i < k; i++ {
		if (prefixBuilder>>(k-i-1))&1 > 0 {
			msgHead = append(msgHead, longMsgs[i]...)
		} else {
			msgHead = append(msgHead, shortMsgs[i]...)
		}
	}

	return append(msgHead, msgTail...)
}

//C54CollisionTreeNode represents a node in a collision tree
//for an iterated hash
type C54CollisionTreeNode struct {
	State       []byte
	NextMessage []byte
	NextNode    *C54CollisionTreeNode
}

//C54CollisionTree generates a collision tree of 2**k initial states
//(may not be distinct) colliding into a single state
func C54CollisionTree(k int) (leaves []*C54CollisionTreeNode) {
	leaves = make([]*C54CollisionTreeNode, 0)
	for i := 0; i < 1<<k; i++ {
		state := GenerateRandomByteSlice(2)
		tmp := C54CollisionTreeNode{state, nil, nil}
		leaves = append(leaves, &tmp)
	}

	thisLayer := leaves

	for len(thisLayer) > 1 {
		fmt.Printf("Starting layer with %v nodes\n", len(thisLayer)/2)
		prevLayer := thisLayer
		thisLayer = make([]*C54CollisionTreeNode, 0)
		for i := 0; i < len(prevLayer); i += 2 {
			msg1, msg2, newState := C54GenerateCollision(prevLayer[i].State, prevLayer[i+1].State)
			prevLayer[i].NextMessage = msg1
			prevLayer[i+1].NextMessage = msg2
			tmp := C54CollisionTreeNode{newState, nil, nil}
			thisLayer = append(thisLayer, &tmp)
			prevLayer[i].NextNode = &tmp
			prevLayer[i+1].NextNode = &tmp
		}
	}
	return
}

//C54NodeBuildMessage traverses a collision tree upward, starting
//at the given node, and concatenates the messages for the paths
func C54NodeBuildMessage(node *C54CollisionTreeNode) (msg []byte) {
	msg = make([]byte, 0)
	for node.NextNode != nil {
		msg = append(msg, node.NextMessage...)
		node = node.NextNode
	}
	return
}

//C54GenerateCollision generates two messages that collide
//under C52MD from the given initial states
func C54GenerateCollision(initState1, initState2 []byte) (msg1, msg2, finalState []byte) {
	for {
		msg1 = GenerateRandomByteSlice(16)
		msg2 = GenerateRandomByteSlice(16)
		finalState = C52MD(msg1, initState1)
		finalState2 := C52MD(msg2, initState2)
		if bytes.Equal(finalState, finalState2) {
			return
		}
	}
}

//C54GeneratePreimage generates a message with the given prefix that, under the given
//initial state, hashes (via C52MD) to the state at the root of the collision tree
func C54GeneratePreimage(msg, initState []byte, leaves []*C54CollisionTreeNode) []byte {
	finalState := C52MD(msg, initState)

	for {
		bridge := GenerateRandomByteSlice(16)
		bridgeState := C52MD(bridge, finalState)
		for _, v := range leaves {
			if bytes.Equal(v.State, bridgeState) {
				preimage := append(msg, bridge...)
				preimage = append(preimage, C54NodeBuildMessage(v)...)
				return preimage
			}
		}

	}
}
