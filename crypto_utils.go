package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"math/bits"
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
