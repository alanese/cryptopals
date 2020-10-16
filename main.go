package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

//TimedGet issues a GET request to the specified URL, and returns
//a response and error, along with the number of milliseconds taken.
func TimedGet(url string) (t int, r *http.Response, err error) {
	startTime := time.Now().UnixNano()
	r, err = http.Get(url)
	stopTime := time.Now().UnixNano()
	t = int((stopTime - startTime) / 1000000)
	return
}

//C31GetOverheadMS sends intentionally bad HMAC
//verification requests to determine the time taken in milliseconds
//by non-comparison parts of verification (e.g. network travel times)
func C31GetOverheadMS(urlFormat string) int {
	attempts := 5
	fakeHmac := make([]byte, 20)
	testURL := fmt.Sprintf(urlFormat, "a", fakeHmac)

	overheadSum0 := 0
	for i := 0; i < attempts; i++ {
		t, r, _ := TimedGet(testURL)
		overheadSum0 += t
		r.Body.Close()
	}

	fakeHmac[0] = 0x01
	testURL = fmt.Sprintf(urlFormat, "a", fakeHmac)
	overheadSum1 := 0
	for i := 0; i < attempts; i++ {
		t, r, _ := TimedGet(testURL)
		overheadSum1 += t
		r.Body.Close()
	}

	if overheadSum0 > overheadSum1 {
		return overheadSum1 / attempts
	}
	return overheadSum0 / attempts

}

//C31GetByteDelay estimates the per-byte compare time
//for the insecure comparison in challenge 31
func C31GetByteDelay(urlformat string, overhead int) int {
	attemptsPerValue := 5
	testHmac := make([]byte, 20)

	maxTime := 0

	for i := 0; i < 256; i++ {
		totalTime := 0
		testHmac[0] = byte(i)
		testURL := fmt.Sprintf(urlformat, "a", testHmac)
		for j := 0; j < attemptsPerValue; j++ {
			t, r, _ := TimedGet(testURL)
			r.Body.Close()
			totalTime += (t - overhead)
		}
		if totalTime > maxTime {
			maxTime = totalTime
		}
	}
	return maxTime / attemptsPerValue
}

func main() {
	//usually need these
	rand.Seed(time.Now().Unix())
	//key := GenerateRandomByteSlice(16)
	m := []byte("hahatryandstopme")
	secret := []byte("THIS IS A SECRET DON'T TELL ANYONE")
	targetHmac := HMACSHA1(secret, m)
	fmt.Printf("%X\n", targetHmac)
	hmac := make([]byte, 20)
	queryURLBase := "http://localhost:8080/?file=%v&signature=%X"

	overheadMs := C31GetOverheadMS(queryURLBase)
	fmt.Printf("Overhead %v ms\n", overheadMs)

	byteDelay := C31GetByteDelay(queryURLBase, overheadMs)
	fmt.Printf("Computed byte delay %v ms", byteDelay)

	for i := range hmac {
		for j := 0; j < 256; j++ {
			hmac[i] = byte(j)
			fmt.Printf("%X\n", hmac)
			queryURL := fmt.Sprintf(queryURLBase, string(m), hmac)
			msDelay, r, _ := TimedGet(queryURL)
			if r.StatusCode == http.StatusOK {
				r.Body.Close()
				break
			}
			if r.StatusCode != http.StatusInternalServerError {
				panic("Unexpected Http status " + strconv.Itoa(r.StatusCode))
			}

			msDelay -= overheadMs
			fmt.Printf("%v ms delay\n", msDelay)
			delayBlocks := int((float64(msDelay) / float64(byteDelay)) + 0.5)
			fmt.Printf("%v blocks\n", delayBlocks)
			r.Body.Close()
			if delayBlocks > i {
				break
			}
		}
	}

	fmt.Printf(" Actual HMAC %X\nGuessed HMAC %X\n", targetHmac, hmac)

}
