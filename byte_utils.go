package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"math/rand"
)

//AllBytesPrintable checks whether all bytes in the slice
//are in the ASCII printable range (0x20-0x7E)
func AllBytesPrintable(b []byte) bool {
	for _, v := range b {
		if v < 0x20 || v > 0x7E {
			return false
		}
	}
	return true
}

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

//AsBytes32LE converts a uint32 into a slice
//of its 4 bytes in little-endian order
func AsBytes32LE(x uint32) []byte {
	b := make([]byte, 4)
	for i := 0; i < 4; i++ {
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

//FromBytes32 converts a slice of bytes into
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

//CompressDEFLATE compresses the byte slice with the DEFLATE
//algorithm
func CompressDEFLATE(s []byte) []byte {
	b := bytes.NewBuffer([]byte{})
	w, _ := flate.NewWriter(b, flate.DefaultCompression)
	w.Write(s)
	w.Flush()
	return b.Bytes()
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

//FindDuplicate returns the indices of a pair of duplicate
//entries in a slice of byte slices. Returns -1, -1 if no
//duplicate is found
func FindDuplicate(b [][]byte) (int, int) {
	for i := 0; i < len(b)-1; i++ {
		for j := i + 1; j < len(b); j++ {
			if bytes.Equal(b[i], b[j]) {
				return i, j
			}
		}
	}
	return -1, -1
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

//IncrementByteSlice replaces b with the next (lexicographically)
//byte slice where each byte is between lower and upper, inclusive.
//If b is the last such slice (i.e. each byte equals upper), it will
//wrap around to the slice where each byte equals lower. Returns the updated
//slice (but modifies b in-place)
func IncrementByteSlice(lower, upper byte, b []byte) []byte {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] > upper || b[i] == 0 {
			b[i] = lower
		} else {
			return b
		}
	}
	return b
}

//IncrementPrintableBytes replaces b with the next slice of bytes
//(lexicographically) composed entirely of printable bytes.
func IncrementPrintableBytes(b []byte) {
	i := len(b) - 1
	for i >= 0 {
		b[i]++
		if b[i] > 126 {
			b[i] = 32
			i--
		} else {
			break
		}
	}
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
