package main

import (
	"math/bits"
)

//SHA1HashPadding computes the padding added to msg
//while SHA-1 hashing it.
func SHA1HashPadding(msg []byte) []byte {
	padding := make([]byte, 0, 64)
	padding = append(padding, 0x80)

	for (len(padding)+len(msg))%64 != 56 {
		padding = append(padding, byte(0))
	}
	ml := uint64(len(msg) * 8)
	padding = append(padding, AsBytes64(ml)...)
	return padding
}

//SHA1Hash computes the SHA-1 digest of the given message
func SHA1Hash(msg []byte) []byte {
	padding := SHA1HashPadding(msg)
	return SHA1HashExtend(append(msg, padding...), 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
}

//SHA1HashExtend computes the SHA-1 digest of the given message,
//starting from the given state. Assumes the given msg is already
//correctly padded
func SHA1HashExtend(msg []byte, h0, h1, h2, h3, h4 uint32) []byte {
	//copy message
	//ml := uint64(len(msg))
	m := make([]byte, 0, len(msg))
	m = append(m, msg...)

	//pad
	//padding := SHA1HashPadding(m)
	//m = append(m, padding...)

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
