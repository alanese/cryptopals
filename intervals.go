package main

import (
	"math/big"
)

//Interval represents a closed interval of real numbers
type Interval struct {
	Min *big.Rat
	Max *big.Rat
}

//Intersects determines whether two (closed) intervals intersect nontrivially
func (i *Interval) Intersects(other Interval) bool {
	return i.Min.Cmp(other.Max) <= 0 && other.Min.Cmp(i.Max) <= 0
}

//Length returns the number of integers in the given interval
func (i *Interval) Length() *big.Int {
	lgth := big.NewInt(0).Sub(RatFloor(i.Max), RatCeil(i.Min))
	return lgth.Add(lgth, big.NewInt(1))
}

//RatCeil returns the ceiling of a *big.Rat
func RatCeil(r *big.Rat) *big.Int {
	m := big.NewInt(0)
	q, m := big.NewInt(0).DivMod(r.Num(), r.Denom(), m)
	if m.Cmp(big.NewInt(0)) == 0 {
		return q
	}
	return q.Add(q, big.NewInt(1))
}

//RatFloor returns the floor of a *big.Rat
func RatFloor(r *big.Rat) *big.Int {
	return big.NewInt(0).Div(r.Num(), r.Denom())
}

//RatMax returns the maximum of two bigRats
func RatMax(r1, r2 *big.Rat) *big.Rat {
	if r1.Cmp(r2) < 0 {
		return r2
	}
	return r1

}

//RatMin returns the minimum of two bigRats
func RatMin(r1, r2 *big.Rat) *big.Rat {
	if r1.Cmp(r2) > 0 {
		return r2
	}
	return r1
}

//UnionIntervals finds the union of two intersecting intervals.
//Panics if the two given intervals do not intersect.
func UnionIntervals(i1, i2 Interval) Interval {
	if !i1.Intersects(i2) {
		panic("Intervals do not intersect")
	}
	u := Interval{}
	if i1.Min.Cmp(i2.Min) < 0 {
		u.Min = i1.Min
	} else {
		u.Min = i2.Min
	}

	if i1.Max.Cmp(i2.Max) > 0 {
		u.Max = i1.Max
	} else {
		u.Max = i2.Max
	}

	return u
}

//AddIntervalToSet unions i into the first element of set it intersects,
//or appends i to the end of set if it doesn't intersect any elements
func AddIntervalToSet(set []Interval, i Interval) []Interval {
	for j := 0; j < len(set); j++ {
		if i.Intersects(set[j]) {
			set[j] = UnionIntervals(i, set[j])
			return set
		}
	}
	return append(set, i)
}

//SimplifyIntervalUnion simplifies a union of intervals to a union of disjoint intervals
func SimplifyIntervalUnion(intervals []Interval) []Interval {
	if len(intervals) <= 1 {
		return intervals
	}
	newSet := intervals
	oldSet := make([]Interval, 0)
	for len(oldSet) != len(newSet) {
		oldSet = make([]Interval, len(newSet))
		copy(oldSet, newSet)
		newSet = make([]Interval, 0)
		for _, intvl := range oldSet {
			newSet = AddIntervalToSet(newSet, intvl)
		}
	}
	return newSet
}
