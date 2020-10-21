// This file contains assorted numeric utility functions
package main

import "math/big"

//ModExp computes (a**x) mod m
func ModExp(a, x, m *big.Int) (r *big.Int) {
	accum := big.NewInt(1)
	expLength := x.BitLen()
	for i := expLength - 1; i >= 0; i-- {
		accum.Mul(accum, accum)
		if x.Bit(i) != 0 {
			accum.Mul(accum, a)
		}
		accum.Mod(accum, m)
	}
	return accum

}

//ModInv computes the multiplicative inverse of x modulo m
//Returns nil if no inverse exists
func ModInv(x, m *big.Int) *big.Int {
	zero := big.NewInt(0)
	t := big.NewInt(0)
	newt := big.NewInt(1)
	r := big.NewInt(0).Set(m)
	newr := big.NewInt(0).Set(x)

	for zero.Cmp(newr) != 0 {
		q := big.NewInt(0).Div(r, newr)
		t, newt = newt, big.NewInt(0).Sub(t, big.NewInt(0).Mul(q, newt))
		r, newr = newr, big.NewInt(0).Sub(r, big.NewInt(0).Mul(q, newr))
	}

	if big.NewInt(1).Cmp(r) < 0 {
		return nil
	}
	if zero.Cmp(t) > 0 {
		t = t.Add(t, m)
	}
	return t
}

//NRoot finds floor(x^(1/n)) via binary search. Requires x > 0.
func NRoot(x *big.Int, n int) *big.Int {
	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)
	N := big.NewInt(int64(n))

	upperBd := big.NewInt(0).Set(x)
	lowerBd := big.NewInt(0)

	midPt := big.NewInt(0)

	r := big.NewInt(0).Sub(upperBd, lowerBd)
	for one.Cmp(r) < 0 {
		midPt = midPt.Div(r, two)
		midPt = midPt.Add(lowerBd, midPt)

		test := big.NewInt(0).Exp(midPt, N, zero)
		c := test.Cmp(x)
		if c == 0 {
			return midPt
		} else if c < 0 {
			lowerBd.Set(midPt)
		} else {
			upperBd.Set(midPt)
		}
		r.Sub(upperBd, lowerBd)
	}
	return lowerBd

}
