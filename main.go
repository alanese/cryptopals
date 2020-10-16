package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	//usually need these
	rand.Seed(time.Now().Unix())
	//key := GenerateRandomByteSlice(16)
	m := []byte("hahatryandstopme")
	secret := []byte("THIS IS A SECRET DON'T TELL ANYONE")
	targetHmac := HMACSHA1(secret, m)

	hmac := C31BreakHash("http://localhost:8080/?file=%v&signature=%X", string(m), true)

	fmt.Printf(" Actual HMAC %X\nGuessed HMAC %X\n", targetHmac, hmac)

}
