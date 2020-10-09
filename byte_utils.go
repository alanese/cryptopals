package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"math/rand"
)

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
