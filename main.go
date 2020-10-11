package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().Unix())
	key := GenerateRandomByteSlice(16)
	iv := GenerateRandomByteSlice(16)
	userdata := "aaaaaaaaaaaaaaaa"
	ctext := Challenge16Func(userdata, key, iv)
	uBytes := []byte(userdata)
	targetText := []byte("aaaaa;admin=true")
	flipper, _ := XorBufs(uBytes, targetText)
	sneakyText := ctext[:16]
	newBlock, _ := XorBufs(flipper, ctext[16:32])
	sneakyText = append(sneakyText, newBlock...)
	sneakyText = append(sneakyText, ctext[32:]...)
	ok := Challenge16AdminCheck(sneakyText, key, iv)
	fmt.Println(ok)
	sneakyDecrypted := DecryptAESCBC(sneakyText, key, iv)
	fmt.Println(string(sneakyDecrypted))

}
