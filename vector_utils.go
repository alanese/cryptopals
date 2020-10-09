package main

import (
	"errors"
	"math"
)

//DotProduct computes the dot product of two int vectors
//Returns a non-nil error if the two supplied vectors are of different lengths
func DotProduct(v1, v2 []int) (int, error) {
	if len(v1) != len(v2) {
		return 0, errors.New("Incompatible vectors")
	}
	tmp := 0
	for i := range v1 {
		tmp += v1[i] * v2[i]
	}
	return tmp, nil
}

//Magnitude computes the magnitude of a vector of ints
func Magnitude(v []int) float64 {
	var total float64 = 0
	for _, k := range v {
		total += float64(k * k)
	}
	return math.Sqrt(total)
}

//VectorAngle computes the angle between two vectors of ints
//Returns a non-nil error if the two vectors are of different lengths
func VectorAngle(v1, v2 []int) (float64, error) {
	if len(v1) != len(v2) {
		return 0, errors.New("Incompatible vectors")
	}
	dp, err := DotProduct(v1, v2)
	if err != nil {
		return 0, err
	}
	magV1 := Magnitude(v1)
	magV2 := Magnitude(v2)
	c := float64(dp) / (magV1 * magV2)
	return math.Acos(c), nil
}
