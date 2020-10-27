package main

import (
	"fmt"
	"math/big"
)

//C47_2a implements step 2a of Bleichenbacher's attack
func C47_2a(c0, B, e, d, n *big.Int) *big.Int {
	lowerBdDenom := big.NewInt(0).Mul(B, big.NewInt(3))
	lowerBd := big.NewRat(0, 1).SetFrac(n, lowerBdDenom)

	s1 := RatCeil(lowerBd)
	for {
		fmt.Printf("Testing s1 = %X\n", s1)
		ctext := big.NewInt(0).Exp(s1, e, n)
		ctext.Mul(c0, ctext)
		ctext.Mod(ctext, n)
		if C47PaddingOracle(ctext.Bytes(), d, n) {
			return s1
		}
		s1.Add(s1, big.NewInt(1))
	}
}

//C47_2b implements step 2b of Bleichenbacher's attack
func C47_2b(c0, prevS, e, d, n *big.Int) *big.Int {
	si := big.NewInt(0).Add(prevS, big.NewInt(1))
	for {
		ctext := big.NewInt(0).Exp(si, e, n)
		ctext.Mul(c0, ctext)
		ctext.Mod(ctext, n)
		if C47PaddingOracle(ctext.Bytes(), d, n) {
			return si
		}

		si.Add(si, big.NewInt(1))
	}
}

//C47_2c implements step 2c of Bleichenbacher's attack
func C47_2c(c0, prevS, B, e, d, n *big.Int, a, b *big.Rat) (*big.Int, *big.Int) {
	one := big.NewInt(1)
	prevSRat := big.NewRat(0, 1).SetInt(prevS)
	BRat := big.NewRat(0, 1).SetInt(B)
	numer1 := big.NewRat(0, 1).Mul(b, prevSRat)
	numer2 := big.NewRat(2, 1)
	numer2.Mul(numer2, BRat)
	numer := big.NewRat(0, 1).Sub(numer1, numer2)

	twoB := big.NewRat(0, 1).Mul(big.NewRat(2, 1), BRat)
	threeB := big.NewRat(0, 1).Mul(big.NewRat(3, 1), BRat)

	twoNInv := big.NewRat(0, 1).SetFrac(big.NewInt(2), n)
	ri := RatCeil(big.NewRat(0, 1).Mul(twoNInv, numer))

	for {
		tmp0 := big.NewInt(0).Mul(ri, n)
		tmp0Rat := big.NewRat(0, 1).SetInt(tmp0)
		tmp0Rat.Add(twoB, tmp0Rat)
		sLowerBd := RatCeil(big.NewRat(0, 1).Quo(tmp0Rat, b))

		tmp1 := big.NewInt(0).Mul(ri, n)
		tmp1Rat := big.NewRat(0, 1).SetInt(tmp1)
		tmp1Rat.Add(threeB, tmp1Rat)
		sUpperBd := RatCeil(big.NewRat(0, 1).Quo(tmp1Rat, a))

		si := big.NewInt(0).Set(sLowerBd)
		for si.Cmp(sUpperBd) < 0 {
			ctext := big.NewInt(0).Exp(si, e, n)
			ctext.Mul(ctext, c0)
			ctext.Mod(ctext, n)
			if C47PaddingOracle(ctext.Bytes(), d, n) {
				return nil, si
			}
			si.Add(si, one)
		}
		ri.Add(ri, one)
	}
}

//C47GetStep3Interval implements a portion of step 3 of Bleichenbacher's attack
func C47GetStep3Interval(a, b *big.Rat, B, r, n, si *big.Int) Interval {
	rn := big.NewInt(0).Mul(r, n)
	twoB := big.NewInt(0).Mul(B, big.NewInt(2))
	threeBMinusOne := big.NewInt(0).Mul(B, big.NewInt(3))
	threeBMinusOne.Sub(threeBMinusOne, big.NewInt(1))

	lowerNumer := big.NewInt(0).Add(twoB, rn)
	upperNumer := big.NewInt(0).Add(threeBMinusOne, rn)

	lowerRat := big.NewRat(0, 1).SetFrac(lowerNumer, si)
	upperRat := big.NewRat(0, 1).SetFrac(upperNumer, si)

	lowerBd := RatMax(a, big.NewRat(0, 1).SetInt(RatCeil(lowerRat)))
	upperBd := RatMin(b, big.NewRat(0, 1).SetInt(RatFloor(upperRat)))

	return Interval{lowerBd, upperBd}
}

//C47_3 implements step 3 of Bleichenbacher's attack
func C47_3(prevM []Interval, B, si, n *big.Int) []Interval {
	one := big.NewInt(1)
	siRat := big.NewRat(0, 1).SetInt(si)
	oneOverN := big.NewRat(0, 1).SetFrac(one, n)
	threeB := big.NewInt(0).Mul(big.NewInt(3), B)
	twoB := big.NewInt(0).Mul(big.NewInt(2), B)
	twoBRat := big.NewRat(0, 1).SetInt(twoB)
	threeBMinusOne := big.NewInt(0).Sub(threeB, one)
	threeBMinusOneRat := big.NewRat(0, 1).SetInt(threeBMinusOne)
	newM := make([]Interval, 0)
	for _, intvl := range prevM {
		a := intvl.Min
		b := intvl.Max

		lowerBd := big.NewRat(0, 1).Mul(a, siRat)
		lowerBd.Sub(lowerBd, threeBMinusOneRat)
		lowerBd.Mul(lowerBd, oneOverN)

		upperBd := big.NewRat(0, 1).Mul(b, siRat)
		upperBd.Sub(upperBd, twoBRat)
		upperBd.Mul(upperBd, oneOverN)

		lowerBdInt := RatCeil(lowerBd)
		upperBdInt := RatFloor(upperBd)

		fmt.Printf("Lower %X\nUpper %X\n", lowerBdInt, upperBdInt)

		r := lowerBdInt
		for r.Cmp(upperBdInt) <= 0 {
			newM = append(newM, C47GetStep3Interval(a, b, B, r, n, si))
			r.Add(r, one)
		}

	}
	fmt.Printf("Pre-simplification %v\n", newM)
	return SimplifyIntervalUnion(newM)
}

//BleichenbacherAttack decrypts msg, given the intended recipient's
//public RSA keypair [e,n]. d is passed only for passing on to the padding
//oracle. The attack assumes the original plaintext was properly padded
//per PKCS#1v1.5
func BleichenbacherAttack(msg []byte, e, d, n *big.Int) []byte {
	msgNum := big.NewInt(0).SetBytes(msg)
	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)

	//set B = 2^(8(k-2))
	B := big.NewInt(int64(len(msg)))
	B = B.Sub(B, two)
	B = B.Mul(B, big.NewInt(8))
	B = B.Exp(two, B, zero)

	//Set initial interval
	initMinInt := big.NewInt(0).Mul(two, B)
	initMaxInt := big.NewInt(0).Mul(big.NewInt(3), B)
	initMaxInt.Sub(initMaxInt, one)

	initMin := big.NewRat(0, 1).SetFrac(initMinInt, big.NewInt(1))
	initMax := big.NewRat(0, 1).SetFrac(initMaxInt, big.NewInt(1))

	initInterval := Interval{initMin, initMax}

	//Set up initial values
	initM := []Interval{initInterval}
	initS := big.NewInt(1)
	initC := big.NewInt(0).Exp(initS, e, n)
	initC.Mul(initC, msgNum)
	initC.Mod(initC, n)

	si := C47_2a(initC, B, e, d, n)
	fmt.Println("Init s computed")
	Mi := C47_3(initM, B, si, n)
	fmt.Println("Init M computed")

	newS := big.NewInt(0).Set(si)
	i := 2
	for {
		fmt.Printf("Beginning iteration i=%v\n", i)
		fmt.Println(Mi)
		if len(Mi) == 1 && Mi[0].Length().Cmp(one) == 0 {
			return RatCeil(Mi[0].Max).Bytes()
		}
		si = newS
		if len(Mi) > 1 {
			newS = C47_2b(initC, si, e, d, n)
		} else {
			_, newS = C47_2c(initC, si, B, e, d, n, Mi[0].Min, Mi[0].Max)
		}
		Mi = C47_3(Mi, B, newS, n)
		fmt.Printf("Mi = %v\n", Mi)
		i++
	}

}

//C47PaddingOracle decrypts m with the RSA private keypair [d, n]
//and checks whether the plaintext is properly paddid according to
//PKCS#1v1.5
func C47PaddingOracle(m []byte, d, n *big.Int) bool {
	pText := RSADecryptPad(m, d, n)
	return RSAPKCS1Validate(pText)
}
