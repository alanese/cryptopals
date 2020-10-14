package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"math/rand"
)

//AsBytes32 converts a uint32 into a slice of
//its 4 bytes in big-endian order
func AsBytes32(x uint32) []byte {
	b := make([]byte, 4)
	for i := 3; i >= 0; i-- {
		b[i] = byte(x & 0x000000FF)
		x >>= 8
	}
	return b
}

//AsBytes64 converts a uint64 into a slice of
//its 8 bytes in big-endian order
func AsBytes64(x uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(x & 0xFF)
		x >>= 8
	}
	return b
}

//FromBytes32 converts a aslice of bytes into
//its equivalent (big-endian) uint32. If the
//slice is more than 4 bytes, the last four will
//effectively be used
func FromBytes32(b []byte) uint32 {
	var x uint32 = 0
	for _, v := range b {
		x <<= 8
		x |= uint32(v)
	}
	return x
}

//Chunkify breakes down a bite slice into slices of length n.
//The last slice may be shorter if len(b) is not a multiple
//of n.
func Chunkify(b []byte, n int) [][]byte {
	chunks := make([][]byte, 0, len(b)/n+1)
	for len(b) > n {
		chunks = append(chunks, b[:n])
		b = b[n:]
	}
	if len(b) > 0 {
		chunks = append(chunks, b)
	}
	return chunks

}

//ContainsDuplicates checks whether a slice of byte slices
//contains any equivalent slices
func ContainsDuplicates(b [][]byte) bool {
	for i := 0; i < len(b)-1; i++ {
		for j := i + 1; j < len(b); j++ {
			if bytes.Equal(b[i], b[j]) {
				return true
			}
		}
	}
	return false
}

//DecodeFileBase64 reads a base64-encrypted file and decodes it
//into a byte slice.
func DecodeFileBase64(fname string) ([]byte, error) {
	tmp, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	txt := make([]byte, base64.StdEncoding.EncodedLen(len(tmp)))
	n, err := base64.StdEncoding.Decode(txt, tmp)
	if err != nil {
		return nil, err
	}
	return txt[:n], nil
}

//EveryNth returns a byte slice composed of every step-th element
//of b, beginning at start
func EveryNth(b []byte, start, step int) []byte {
	if step <= 0 {
		panic("Step cannot be negative, stop that")
	}
	tmp := []byte{}
	i := start
	for i < len(b) {
		tmp = append(tmp, b[i])
		i += step
	}
	return tmp
}

//GenerateRandomByteSlice generates a random slice
//of bytes of the given length
func GenerateRandomByteSlice(length int) []byte {
	s := make([]byte, length)
	for i := range s {
		s[i] = byte(rand.Intn(256))
	}
	return s
}

//HexToB64 converts a byte slice of hex values to base64
func HexToB64(src []byte) ([]byte, error) {
	tmp := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(tmp, src)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(tmp)))
	base64.StdEncoding.Encode(dst, tmp)
	return dst, nil
}

//NCopiesOfN returns a byte slice composed of n copies of
//the byte n. Returns an empty slice if n is out of
//range for a byte.
func NCopiesOfN(n int) []byte {
	if n < 0 || n > 255 {
		return []byte{}
	}
	tmp := make([]byte, n)
	for i := range tmp {
		tmp[i] = byte(n)
	}
	return tmp
}

//PadLeft pads a byte slice by adding copies of a given
//byte to the left; returns the original slice if longer
//than the specified length
func PadLeft(orig []byte, pad byte, length int) []byte {
	if len(orig) >= length {
		return orig
	}
	b := bytes.NewBuffer([]byte{})
	toAdd := length - len(orig)
	for i := 0; i < toAdd; i++ {
		b.WriteByte(pad)
	}
	b.Write(orig)
	return b.Bytes()
}

//LinesFromFile reads data from a file and splits it into lines
//The function uses \n for its newline
func LinesFromFile(fname string) ([][]byte, error) {
	f, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(f, []byte{byte(0x0A)}) //0x0A is an ASCII line feed
	return lines, nil
}

//RightOnes gets a uint32 where the rightmost n bits
//are 1 and the rest are 0.
func RightOnes(n int) uint32 {
	return (uint32(1) << n) - 1
}
