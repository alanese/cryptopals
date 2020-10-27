package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"math/bits"
	"math/rand"
	"net/http"
	"time"
)

//DetectAESECB attempts to detect whether a byte slice
//has likely been encrypted with AES-ECB.
//False positives are very unlikely; false negatives not so much.
func DetectAESECB(ctext []byte) bool {
	for i := 0; i < 16; i++ {
		c := Chunkify(ctext[i:], 16)
		if ContainsDuplicates(c) {
			return true
		}
	}
	return false
}

//FileFreqCount counts the number of occurrences of each byte value in a file
func FileFreqCount(fname string) ([256]int, error) {
	f, err := ioutil.ReadFile(fname)
	if err != nil {
		return [256]int{}, err
	}
	return FreqCount(f), nil
}

//FreqCount counts the number of occurrences of each byte value in a slice
func FreqCount(sample []byte) [256]int {
	var counts [256]int
	for _, v := range sample {
		counts[v]++
	}
	return counts
}

//GenerateCTRKeystreamBlock generates a CTR keystream block
//with the given key, nonce, and counter. len(nonce) + len(counter)
//must be the block length.
func GenerateCTRKeystreamBlock(key, nonce, counter []byte) []byte {
	notPtext := append(nonce, counter...)
	return EncryptAESECB(notPtext, key)
}

//GenerateCTRKeystream generates the given number of blocks
//of an AES-CTR keystream given key, nonce, and a counter function.
func GenerateCTRKeystream(blocks int, key, nonce []byte, counter func(int) []byte) []byte {
	stream := make([]byte, 0, 16*blocks)
	for i := 0; i < blocks; i++ {
		nextBlock := GenerateCTRKeystreamBlock(key, nonce, counter(i))
		stream = append(stream, nextBlock...)
	}
	return stream
}

//LittleEndianCounter is a counter function for use with
//GenerateCTRKeystream.
func LittleEndianCounter(i int) []byte {
	counter := make([]byte, 8)
	for j := 0; j < 8; j++ {
		counter[j] = byte((i >> (j * 8)) & 0xFF)
	}
	return counter
}

//GuessRepeatedXorKeyLen guesses the length of the key
//for a ciphertext encrypted with repeating-key XOR
func GuessRepeatedXorKeyLen(ctext []byte, min, max int) int {
	if max > 2*len(ctext) {
		panic("Insufficient data for given max")
	}
	if min > max {
		panic("Min must be less than max")
	}
	bestDist := 8.0
	var bestLen int
	for i := min; i <= max; i++ {
		distSum := 0.0
		j := 0
		testSlice := ctext
		for len(testSlice) > 2*i {
			block1 := testSlice[:i]
			block2 := testSlice[i : 2*i]
			d, _ := NormalizedEditDistance(block1, block2)
			distSum += d
			j++
			testSlice = testSlice[2*i:]
		}
		distSum = distSum / float64(j)
		if distSum < bestDist {
			bestDist = distSum
			bestLen = i
		}
	}

	return bestLen
}

//HammingDistance computes the Hamming distance between two bytes
//(i.e. number of bits that differ).
func HammingDistance(b1, b2 byte) int {
	return bits.OnesCount8(uint8(b1 ^ b2))
}

//HammingDistanceSlice computes the Hamming distance between two
//byte slices. Returns a non-nil error if the slices are of unequal length
func HammingDistanceSlice(b1, b2 []byte) (int, error) {
	if len(b1) != len(b2) {
		return 0, errors.New("Incompatible byte slices")
	}
	ct := 0
	for i := range b1 {
		ct += HammingDistance(b1[i], b2[i])
	}
	return ct, nil
}

//NormalizedEditDistance returns the edit distance between two
//byte slices divided by their length. Returns a non-nil error
//if the slices are of unequal length
func NormalizedEditDistance(b1, b2 []byte) (float64, error) {
	d, err := HammingDistanceSlice(b1, b2)
	if err != nil {
		return 0, err
	}
	return float64(d) / float64(len(b1)), nil
}

//PKCSPad pads a byte slice using PKCS#7 for the given block size
func PKCSPad(txt []byte, blockSize int) []byte {
	toAdd := blockSize - (len(txt) % blockSize)
	for i := 0; i < toAdd; i++ {
		txt = append(txt, byte(toAdd))
	}
	return txt
}

//PKCS15Pad pads the input to the given length per PKCS#1v1.5
//(block type 02). Returns a non-nil error if the given length
//is too short to properly pad the message.
func PKCS15Pad(txt []byte, length int) ([]byte, error) {
	if len(txt) > length-11 {
		return nil, fmt.Errorf("Length too short to accommodate padding")
	}
	padded := []byte{0x00, 0x02}
	for len(padded) < length-len(txt)-1 {
		padded = append(padded, byte(rand.Intn(254)+1))
	}
	padded = append(padded, 0x00)
	padded = append(padded, txt...)
	return padded, nil
}

//RSAPKCS1Validate determines whether the byte slice is
//properly padded for RSA encryption according to PKCS#1v1.5
//Not a cryptographically secure check as it has a timing leak
func RSAPKCS1Validate(eb []byte) bool {
	if len(eb) < 11 {
		return false
	}
	if eb[0] != 0x00 {
		return false
	}
	if eb[1] != 0x02 {
		return false
	}
	for i := 2; i < 9; i++ {
		if eb[i] == 0x00 {
			return false
		}
	}
	for i := 9; i < len(eb); i++ {
		if eb[i] == 0x00 {
			return true
		}
	}
	return false
}

//ScoreText computes a score for a potential plaintext.
//The score is the angle between the vector for the plaintext's
//character distribution and the vector for the target distribution.
//Lower scores are better.
func ScoreText(ptext []byte, targetDist [256]int) float64 {
	textDist := FreqCount(ptext)
	score, err := VectorAngle(textDist[:], targetDist[:])
	if err != nil {
		panic("WHAT HAPPEN") // this should never happen
	}
	return score
}

//StripPKCS15Padding strips PKCS#1v1.5 padding (block type 02)
//from the byte slice. Returns a non-nil error if the block
//is not validly padded.
func StripPKCS15Padding(eb []byte) ([]byte, error) {
	if len(eb) < 11 {
		return nil, fmt.Errorf("Block is not PKCS1.5-padded")
	}
	if eb[0] != 0x00 || eb[1] != 0x02 {
		return nil, fmt.Errorf("Block is not PKCS1.5-padded")
	}
	for i := 2; i < 9; i++ {
		if eb[i] == 0x00 {
			return nil, fmt.Errorf("Block is not PKCS1.5-padded")
		}
	}
	for i := 9; i < len(eb)-1; i++ {
		if eb[i] == 0x00 {
			return eb[i+1:], nil
		}
	}
	if eb[len(eb)-1] == 0x00 {
		return []byte{}, nil
	}
	return nil, fmt.Errorf("Block is not PKCS1.5-padded")
}

//StripPKCS7Padding strips the PKCS#7 padding from
//a byte slice. Returns a non-nil error if the text
//length is not a multiple of the block size, or
//if the text is not correctly PKCS padded.
func StripPKCS7Padding(txt []byte, blockLength int) ([]byte, error) {
	if len(txt)%blockLength != 0 {
		return nil, errors.New("Text length not a multiple of block size")
	}

	for i := 1; i <= blockLength; i++ {
		testEnd := NCopiesOfN(i)
		if bytes.HasSuffix(txt, testEnd) {
			return txt[:len(txt)-i], nil
		}
	}

	return nil, errors.New("Text is not PKCS7-padded")

}

//TimedGet issues a GET request to the specified URL, and returns
//a response and error, along with the number of milliseconds taken.
//The r and err return values are passed through directly from http.Get()
func TimedGet(url string) (t int, r *http.Response, err error) {
	startTime := time.Now().UnixNano()
	r, err = http.Get(url)
	stopTime := time.Now().UnixNano()
	t = int((stopTime - startTime) / 1000000)
	return
}

//XorBufs computes the bitwise xor of two byte slices
//Returns a non-nil error if the two slices are of different lengths
func XorBufs(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, errors.New("Buffers of unequal length")
	}
	tmp := make([]byte, len(b1))
	for i := range b1 {
		tmp[i] = b1[i] ^ b2[i]
	}
	return tmp, nil
}
