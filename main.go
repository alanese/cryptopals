package main

import (
	"crypto/sha1"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

//C44DSASHA1Sig stores a message and its signature for challenge 44
type C44DSASHA1Sig struct {
	Msg    []byte
	Digest []byte
	R      *big.Int
	S      *big.Int
}

func RecoverDSAPrivateKey(digest []byte, r, s, k, q *big.Int) *big.Int {
	rInv := big.NewInt(0).ModInverse(r, q)
	tmp := big.NewInt(0).Mul(s, k)
	tmp.Sub(tmp, big.NewInt(0).SetBytes(digest))
	tmp.Mul(tmp, rInv)
	x := tmp.Mod(tmp, q)
	return x
}

func C44FindCommonK(md1, md2 []byte, s1, s2, q *big.Int) *big.Int {
	md1Num := big.NewInt(0).SetBytes(md1)
	md2Num := big.NewInt(0).SetBytes(md2)

	numer := big.NewInt(0).Sub(md1Num, md2Num)
	denom := big.NewInt(0).Sub(s1, s2)

	denomInv := big.NewInt(0).ModInverse(denom, q)
	if denomInv == nil {
		return nil
	}
	k := big.NewInt(0).Mul(numer, denomInv)
	k.Mod(k, q)
	return k
}

func C44FindKey(fname string, pubkey, p, q, g *big.Int) *big.Int {
	//Parse file
	lines, _ := LinesFromFile(fname)
	sigs := make([]C44DSASHA1Sig, 0)
	for i := 0; i < len(lines); i += 4 {
		msg := lines[i][5:]
		s, _ := big.NewInt(0).SetString(string(lines[i+1][3:]), 10)
		r, _ := big.NewInt(0).SetString(string(lines[i+2][3:]), 10)
		digestNum, _ := big.NewInt(0).SetString(string(lines[i+3][3:]), 16)
		digest := digestNum.Bytes()
		fmt.Println(string(lines[i+3][3:]))
		sigs = append(sigs, C44DSASHA1Sig{msg, digest, r, s})
	}
	for i := 0; i < len(sigs); i++ {
		for j := i + 1; j < len(sigs); j++ {
			fmt.Printf("Starting %v,%v\n------\n", i, j)
			candidateK := C44FindCommonK(sigs[i].Digest, sigs[j].Digest, sigs[i].S, sigs[j].S, q)
			if candidateK == nil || big.NewInt(0).Cmp(candidateK) == 0 {
				fmt.Println("Impossible K\n-----")
				continue
			}
			fmt.Printf("Candidate K: %X\n", candidateK)
			candidateX := RecoverDSAPrivateKey(sigs[i].Digest, sigs[i].R, sigs[i].S, candidateK, q)
			candidateR, candidateS, err := DSASignSHA1Forcek(sigs[i].Msg, candidateK, candidateX, p, q, g)
			if err != nil {
				fmt.Println("Error signing with candidate X\n-----")
				continue
			}
			fmt.Printf("Candidate R: %X\n          R: %X\nCandidate S: %X\n          S: %X\n", sigs[i].R, candidateR, sigs[i].S, candidateS)
			if candidateR.Cmp(sigs[i].R) == 0 && candidateS.Cmp(sigs[i].S) == 0 {
				return candidateX
			}
			fmt.Println("Unequal signatures\n------")
		}
	}

	return nil
}

func main() {
	rand.Seed(time.Now().Unix())

	p, _ := big.NewInt(0).SetString(C43pString, 16)
	g, _ := big.NewInt(0).SetString(C43gString, 16)
	q, _ := big.NewInt(0).SetString(C43qString, 16)

	x := C44FindKey("44.txt", big.NewInt(0), p, q, g)
	fmt.Printf("%X\n", x)

	xStr := fmt.Sprintf("%x", x)
	xHash := sha1.Sum([]byte(xStr))
	fmt.Printf("%x\n", xHash)

}
