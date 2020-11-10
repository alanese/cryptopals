package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"time"
)

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

func main() {
	rand.Seed(time.Now().Unix())
	//C50ForgeMsg()
	k := 4
	initState := GenerateRandomByteSlice(2)
	trueMsg := GenerateRandomByteSlice(16 * (1 << k))
	forged := C53ForgeMessage(trueMsg, initState, k)
	fmt.Printf("Original %x\n  Forged %x\n", trueMsg, forged)
	origHash := C52MD(trueMsg, initState)
	forgedHash := C52MD(forged, initState)
	fmt.Printf("Orig hash %x\nForg hash %x\n", origHash, forgedHash)

}
