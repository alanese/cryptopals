package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/crypto/twofish"
)

func C52MD(M, H []byte) []byte {
	key := PadLeft(H, 0x00, 16)
	msg := M
	for i := 0; i*16 < len(msg); i++ {
		longKey := EncryptAESECB(msg[16*i:16*(i+1)], key)
		key = PadLeft(longKey[14:], 0x00, 16)
	}
	return key[14:]
}
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

func main() {
	rand.Seed(time.Now().Unix())
	//C50ForgeMsg()
	initState := GenerateRandomByteSlice(2)

	colls := C52GenerateManyCollisions(initState, 8)
	tfHashes := make([][]byte, len(colls))
	for i, v := range colls {
		//fmt.Printf("I: %x\nH: %x\n", v, C52MD(v, initState))
		tfHashes[i] = C52TwofishMD(v, initState)
	}
	c1, c2 := FindDuplicate(tfHashes)
	if c1 >= 0 {
		fmt.Printf("I1: %x\nI2: %x\nH1: %x\nH2: %x\n", colls[c1], colls[c2], tfHashes[c1], tfHashes[c2])
	} else {
		fmt.Printf("No collision found\n")
	}

}
