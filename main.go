package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().Unix())
	key := GenerateRandomByteSlice(16)

	forgedToken := Challenge26ForgeData(key)
	ok := Challenge26AdminCheck(forgedToken, key)
	fmt.Println(ok)

}
