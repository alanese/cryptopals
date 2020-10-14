package main

import (
	"math/bits"
)

//SHA1Hash computes the SHA-1 digest of the given message
func SHA1Hash(msg []byte) []byte {
	//setup initial values
	var h0 uint32 = 0x67452301
	var h1 uint32 = 0xEFCDAB89
	var h2 uint32 = 0x98BADCFE
	var h3 uint32 = 0x10325476
	var h4 uint32 = 0xC3D2E1F0

	//copy message
	ml := uint64(len(msg))
	m := make([]byte, len(msg))
	m = append(m, msg...)

	//pad
	m = append(m, byte(0x80))

	for (len(m)*8)%512 != 448 {
		m = append(m, byte(0))
	}
	m = append(m, AsBytes64(ml)...)

	//break into 512-bit = 64-byte chunks
	chunks := Chunkify(m, 64)

	var f, k uint32

	for _, chunk := range chunks {
		//initialize message schedule
		w := make([]uint32, 80)
		for i := 0; i < 16; i++ {
			w[i] = FromBytes32(chunk[4*i : 4*(i+1)])
		}
		for i := 16; i < 80; i++ {
			w[i] = bits.RotateLeft32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
		}

		//initialize chunk values
		a := h0
		b := h1
		c := h2
		d := h3
		e := h4

		//main loop
		for i := 0; i < 80; i++ {
			if i <= 19 {
				f = (b & c) | ((^b) & d)
				k = 0x5A827999
			} else if i <= 39 {
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			} else if i <= 59 {
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			} else {
				f = b ^ c ^ d
				k = 0xCA62C1D6
			}

			tmp := bits.RotateLeft32(a, 5) + f + e + k + w[i]

			e = d
			d = c
			c = bits.RotateLeft32(b, 30)
			b = a
			a = tmp
		}

		//add to result so far
		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
	}
	digest := make([]byte, 0, 40)
	digest = append(digest, AsBytes32(h0)...)
	digest = append(digest, AsBytes32(h1)...)
	digest = append(digest, AsBytes32(h2)...)
	digest = append(digest, AsBytes32(h3)...)
	digest = append(digest, AsBytes32(h4)...)
	return digest
}

//SHA1MAC computes a secret-prefix MAC using SHA-1
func SHA1MAC(msg, key []byte) []byte {
	return SHA1Hash(append(key, msg...))
}
