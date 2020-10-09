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
	sneakyBit := "admin" + string([]byte{11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11})
	sneakyEmail := "tom@exampl" + sneakyBit + "e.com"
	profile := ProfileFor(sneakyEmail)
	eProfile := EncryptProfile(profile, key)
	adminEnding := eProfile[16:32]
	regularEmail := "tom@example.com"
	regularEProfile := EncryptProfile(ProfileFor(regularEmail), key)
	adminStart := regularEProfile[:48]
	adminEProfile := append(adminStart, adminEnding...)
	adminDProfile, _ := DecryptParseProfile(adminEProfile, key)
	jsonified, _ := json.Marshal(adminDProfile)
	fmt.Println(string(jsonified))
}
