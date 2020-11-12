package main

import (
	"bytes"
	"fmt"
	"math/bits"
	"math/rand"
	"time"
)

//GetBit returns the value of the nth bit
//of a uint32 where bit 0 is the LSB and bit 31
//is the MSB
func GetBit(x uint32, n int) int {
	return int((x >> n) & 1)
}

//BitsEqual checks if the nth bit of x1 and
//the nth bit of x2 are equal
func BitsEqual(x1, x2 uint32, n int) bool {
	return ((x1^x2)>>n)&1 == 0
}

//ClearBit returns a copy of x with the nth bit cleared
func ClearBit(x uint32, n int) uint32 {
	return x &^ (1 << n)
}

//SetBit returns a copy of x with the nth bit set
func SetBit(x uint32, n int) uint32 {
	return x | (1 << n)
}

//MatchBit returns a copy of tgt with its nth bit set
//to the nth bit of src
func MatchBit(tgt, src uint32, n int) uint32 {
	return tgt ^ ((tgt ^ src) & (1 << n))
}

//C55GenerateMessage generates a slice of 32-bit words
//satisfying all 95 first-round conditions from Wang's
//paper (plus an additional condition from Naito et al)
//and seven second-round constraints.
func C55GenerateMessage() []uint32 {
	m := make([]uint32, 16)
	a := make([]uint32, 6)
	b := make([]uint32, 5)
	c := make([]uint32, 5)
	d := make([]uint32, 6)
	a[0] = 0x67452301
	b[0] = 0xefcdab89
	c[0] = 0x98badcfe
	d[0] = 0x10325476

	m[0] = rand.Uint32()
	a[1] = MD4Phi0(a[0], b[0], c[0], d[0], m[0], 3)
	a[1] = MatchBit(a[1], b[0], 6)
	m[0] = bits.RotateLeft32(a[1], -3) - a[0] - MD4F(b[0], c[0], d[0])

	m[1] = rand.Uint32()
	d[1] = MD4Phi0(d[0], a[1], b[0], c[0], m[1], 7)
	d[1] = ClearBit(d[1], 6)
	d[1] = MatchBit(d[1], a[1], 7)
	d[1] = MatchBit(d[1], a[1], 10)
	m[1] = bits.RotateLeft32(d[1], -7) - d[0] - MD4F(a[1], b[0], c[0])

	m[2] = rand.Uint32()
	c[1] = MD4Phi0(c[0], d[1], a[1], b[0], m[2], 11)
	c[1] = SetBit(c[1], 6)
	c[1] = SetBit(c[1], 7)
	c[1] = ClearBit(c[1], 10)
	c[1] = MatchBit(c[1], d[1], 25)
	m[2] = bits.RotateLeft32(c[1], -11) - c[0] - MD4F(d[1], a[1], b[0])

	m[3] = rand.Uint32()
	b[1] = MD4Phi0(b[0], c[1], d[1], a[1], m[3], 19)
	b[1] = SetBit(b[1], 6)
	b[1] = ClearBit(b[1], 7)
	b[1] = ClearBit(b[1], 10)
	b[1] = ClearBit(b[1], 25)
	m[3] = bits.RotateLeft32(b[1], -19) - b[0] - MD4F(c[1], d[1], a[1])

	m[4] = rand.Uint32()
	a[2] = MD4Phi0(a[1], b[1], c[1], d[1], m[4], 3)
	a[2] = SetBit(a[2], 7)
	a[2] = SetBit(a[2], 10)
	a[2] = MatchBit(a[2], b[1], 13)
	a[2] = ClearBit(a[2], 25)
	m[4] = bits.RotateLeft32(a[2], -3) - a[1] - MD4F(b[1], c[1], d[1])

	m[5] = rand.Uint32()
	d[2] = MD4Phi0(d[1], a[2], b[1], c[1], m[5], 7)
	d[2] = ClearBit(d[2], 13)
	d[2] = MatchBit(d[2], a[2], 18)
	d[2] = MatchBit(d[2], a[2], 19)
	d[2] = MatchBit(d[2], a[2], 20)
	d[2] = MatchBit(d[2], a[2], 21)
	d[2] = SetBit(d[2], 25)
	m[5] = bits.RotateLeft32(d[2], -7) - d[1] - MD4F(a[2], b[1], c[1])

	m[6] = rand.Uint32()
	c[2] = MD4Phi0(c[1], d[2], a[2], b[1], m[6], 11)
	c[2] = MatchBit(c[2], d[2], 12)
	c[2] = ClearBit(c[2], 13)
	c[2] = MatchBit(c[2], d[2], 14)
	c[2] = ClearBit(c[2], 18)
	c[2] = ClearBit(c[2], 19)
	c[2] = SetBit(c[2], 20)
	c[2] = ClearBit(c[2], 21)
	m[6] = bits.RotateLeft32(c[2], -11) - c[1] - MD4F(d[2], a[2], b[1])

	m[7] = rand.Uint32()
	b[2] = MD4Phi0(b[1], c[2], d[2], a[2], m[7], 19)
	b[2] = SetBit(b[2], 12)
	b[2] = SetBit(b[2], 13)
	b[2] = ClearBit(b[2], 14)
	b[2] = MatchBit(b[2], c[2], 16)
	b[2] = ClearBit(b[2], 18)
	b[2] = ClearBit(b[2], 19)
	b[2] = ClearBit(b[2], 20)
	b[2] = ClearBit(b[2], 21)
	m[7] = bits.RotateLeft32(b[2], -19) - b[1] - MD4F(c[2], d[2], a[2])

	m[8] = rand.Uint32()
	a[3] = MD4Phi0(a[2], b[2], c[2], d[2], m[8], 3)
	a[3] = SetBit(a[3], 12)
	a[3] = SetBit(a[3], 13)
	a[3] = SetBit(a[3], 14)
	a[3] = ClearBit(a[3], 16)
	a[3] = ClearBit(a[3], 18)
	a[3] = ClearBit(a[3], 19)
	a[3] = ClearBit(a[3], 20)
	a[3] = MatchBit(a[3], b[2], 22)
	a[3] = SetBit(a[3], 21)
	a[3] = MatchBit(a[3], b[2], 25)
	m[8] = bits.RotateLeft32(a[3], -3) - a[2] - MD4F(b[2], c[2], d[2])

	m[9] = rand.Uint32()
	d[3] = MD4Phi0(d[2], a[3], b[2], c[2], m[9], 7)
	d[3] = SetBit(d[3], 12)
	d[3] = SetBit(d[3], 13)
	d[3] = SetBit(d[3], 14)
	d[3] = ClearBit(d[3], 16)
	d[3] = ClearBit(d[3], 19)
	d[3] = SetBit(d[3], 20)
	d[3] = SetBit(d[3], 21)
	d[3] = ClearBit(d[3], 22)
	d[3] = SetBit(d[3], 25)
	d[3] = MatchBit(d[3], a[3], 29)
	m[9] = bits.RotateLeft32(d[3], -7) - d[2] - MD4F(a[3], b[2], c[2])

	m[10] = rand.Uint32()
	c[3] = MD4Phi0(c[2], d[3], a[3], b[2], m[10], 11)
	c[3] = SetBit(c[3], 16)
	c[3] = ClearBit(c[3], 19)
	c[3] = ClearBit(c[3], 20)
	c[3] = ClearBit(c[3], 21)
	c[3] = ClearBit(c[3], 22)
	c[3] = ClearBit(c[3], 25)
	c[3] = SetBit(c[3], 29)
	c[3] = MatchBit(c[3], d[3], 31)
	m[10] = bits.RotateLeft32(c[3], -11) - c[2] - MD4F(d[3], a[3], b[2])

	m[11] = rand.Uint32()
	b[3] = MD4Phi0(b[2], c[3], d[3], a[3], m[11], 19)
	b[3] = ClearBit(b[3], 19)
	b[3] = SetBit(b[3], 20)
	b[3] = SetBit(b[3], 21)
	b[3] = MatchBit(b[3], c[3], 22)
	b[3] = SetBit(b[3], 25)
	b[3] = ClearBit(b[3], 29)
	b[3] = ClearBit(b[3], 31)
	m[11] = bits.RotateLeft32(b[3], -19) - b[2] - MD4F(c[3], d[3], a[3])

	m[12] = rand.Uint32()
	a[4] = MD4Phi0(a[3], b[3], c[3], d[3], m[12], 3)
	a[4] = ClearBit(a[4], 22)
	a[4] = ClearBit(a[4], 25)
	a[4] = MatchBit(a[4], b[3], 26)
	a[4] = MatchBit(a[4], b[3], 28)
	a[4] = SetBit(a[4], 29)
	a[4] = ClearBit(a[4], 31)
	m[12] = bits.RotateLeft32(a[4], -3) - a[3] - MD4F(b[3], c[3], d[3])

	m[13] = rand.Uint32()
	d[4] = MD4Phi0(d[3], a[4], b[3], c[3], m[13], 7)
	d[4] = ClearBit(d[4], 22)
	d[4] = ClearBit(d[4], 25)
	d[4] = SetBit(d[4], 26)
	d[4] = SetBit(d[4], 28)
	d[4] = ClearBit(d[4], 29)
	d[4] = SetBit(d[4], 31)
	m[13] = bits.RotateLeft32(d[4], -7) - d[3] - MD4F(a[4], b[3], c[3])

	m[14] = rand.Uint32()
	c[4] = MD4Phi0(c[3], d[4], a[4], b[3], m[14], 11)
	c[4] = MatchBit(c[4], d[4], 18)
	c[4] = SetBit(c[4], 22)
	c[4] = SetBit(c[4], 25)
	c[4] = ClearBit(c[4], 26)
	c[4] = ClearBit(c[4], 28)
	c[4] = ClearBit(c[4], 29)
	m[14] = bits.RotateLeft32(c[4], -11) - c[3] - MD4F(d[4], a[4], b[3])

	m[15] = rand.Uint32()
	b[4] = MD4Phi0(b[3], c[4], d[4], a[4], m[15], 19)
	b[4] = ClearBit(b[4], 18)
	b[4] = SetBit(b[4], 25)
	b[4] = SetBit(b[4], 26)
	b[4] = SetBit(b[4], 28)
	b[4] = ClearBit(b[4], 29)
	b[4] = MatchBit(b[4], c[4], 31) //per Naito et al 2005
	m[15] = bits.RotateLeft32(b[4], -19) - b[3] - MD4F(c[4], d[4], a[4])

	a[5] = MD4Phi1(a[4], b[4], c[4], d[4], m[0], 3)
	a[5] = MatchBit(a[5], c[4], 18)
	a[5] = SetBit(a[5], 25)
	a[5] = ClearBit(a[5], 26)
	a[5] = SetBit(a[5], 28)
	a[5] = SetBit(a[5], 31)
	m[0] = bits.RotateLeft32(a[5], -3) - a[4] - MD4G(b[4], c[4], d[4]) - 0x5a827999
	a[1] = MD4Phi0(a[0], b[0], c[0], d[0], m[0], 3)
	m[1] = bits.RotateLeft32(d[1], -7) - d[0] - MD4F(a[1], b[0], c[0])
	m[2] = bits.RotateLeft32(c[1], -11) - c[0] - MD4F(d[1], a[1], b[0])
	m[3] = bits.RotateLeft32(b[1], -19) - b[0] - MD4F(c[1], d[1], a[1])
	m[4] = bits.RotateLeft32(a[2], -3) - a[1] - MD4F(b[1], c[1], d[1])

	d[5] = MD4Phi1(d[4], a[5], b[4], c[4], m[4], 5)
	d[5] = MatchBit(d[5], b[4], 28)
	d[5] = MatchBit(d[5], b[4], 31)
	m[4] = bits.RotateLeft32(d[5], -5) - d[4] - MD4G(a[5], b[4], c[4]) - 0x5a827999
	a[2] = MD4Phi0(a[1], b[1], c[1], d[1], m[4], 3)
	m[5] = bits.RotateLeft32(d[2], -7) - d[1] - MD4F(a[2], b[1], c[1])
	m[6] = bits.RotateLeft32(c[2], -11) - c[1] - MD4F(d[2], a[2], b[1])
	m[7] = bits.RotateLeft32(b[2], -19) - b[1] - MD4F(c[2], d[2], a[2])
	m[8] = bits.RotateLeft32(a[3], -3) - a[2] - MD4F(b[2], c[2], d[2])

	return m
}

//C55CreateMPrime computes M + deltaM as given in Wang's paper
func C55CreateMPrime(m []uint32) []uint32 {
	mPrime := make([]uint32, len(m))
	copy(mPrime, m)
	mPrime[1] += 1 << 31
	mPrime[2] += (1<<31 - 1<<28)
	mPrime[12] -= 1 << 16
	return mPrime
}

//C55FindCollision generates a pair of 64-byte slices which
//collide under MD4. Returns nils if no collision is found after
//maxAttempts attempts.
func C55FindCollision(maxAttempts int, verbose bool) (m1, m2, digest []byte) {
	var m, mPrime []uint32
	var mBytes, mPrimeBytes []byte
	var mDigest, mPrimeDigest []byte

	startTime := time.Now()
	for i := 0; i < maxAttempts; i++ {
		if i%1000 == 0 && verbose {
			fmt.Printf("Attempt %v:\n", i)
		}
		m = C55GenerateMessage()
		mPrime = C55CreateMPrime(m)

		mBytes = make([]byte, len(m)*4)
		mPrimeBytes = make([]byte, len(mPrime)*4)
		for i := range m {
			copy(mBytes[4*i:], AsBytes32LE(m[i]))
			copy(mPrimeBytes[4*i:], AsBytes32LE(mPrime[i]))
		}

		mDigest = MD4Hash(mBytes)
		mPrimeDigest = MD4Hash(mPrimeBytes)

		if bytes.Equal(mDigest, mPrimeDigest) {
			if verbose {
				fmt.Printf(" M: %x\nM': %x\n", mBytes, mPrimeBytes)
				fmt.Printf(" M digest: %x\nM' digest: %x\n", mDigest, mPrimeDigest)
				endTime := time.Now()
				elapsedTime := endTime.Unix() - startTime.Unix()
				fmt.Printf("Start time: %v\nEnd time: %v\n", startTime, endTime)
				fmt.Printf("Elapsed time: %vs\n", elapsedTime)
			}
			return mBytes, mPrimeBytes, mDigest
		}
	}
	if verbose {
		fmt.Println("No collision found")
	}
	return nil, nil, nil
}
func main() {
	rand.Seed(time.Now().Unix())

	_, _, _ = C55FindCollision(1000000, true)

}
