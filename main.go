package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().Unix())
	key := GenerateRandomByteSlice(16)
	adminEProfile := CreateEncryptedAdminProfile(key)
	adminDProfile, _ := DecryptParseProfile(adminEProfile, key)
	jsonified, _ := json.Marshal(adminDProfile)
	fmt.Println(string(jsonified))
}
