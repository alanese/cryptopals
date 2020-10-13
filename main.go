package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().Unix())
	token := C24GenerateResetToken("me")
	fmt.Println(C24ValidateToken(token))
	time.Sleep(3 * time.Second)
	fmt.Println(C24ValidateToken(token))

}
