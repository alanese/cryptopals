package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().Unix())
	secretSeed := rand.Uint32()

	t := NewTwister(secretSeed)

	cloned := *CloneTwister(&t)

	fmt.Printf("Original %X\n   Clone %X\n", t.Next(), cloned.Next())

}
