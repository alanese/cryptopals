package main

const twisterLength = 624

//Twister is a Mersenne Twister PRNG, implementing MT19937
type Twister struct {
	x     [twisterLength]uint32
	index int
}

//NewTwister creates a new instance of Twister with
//the given seed.
func NewTwister(seed uint32) Twister {
	t := Twister{}
	t.index = twisterLength
	t.x[0] = seed
	for i := 1; i < twisterLength; i++ {
		t.x[i] = 1812433253*(t.x[i-1]^(t.x[i-1]>>30)) + uint32(i)
	}
	return t

}

//Next gets the next uint32 value from a Twister
func (t *Twister) Next() uint32 {
	if t.index >= twisterLength {
		t.twist()
	}
	y := t.x[t.index]
	y ^= (y >> 11)
	y ^= ((y << 7) & 0x9D2C5680)
	y ^= ((y << 15) & 0xEFC60000)
	y ^= (y >> 18)
	t.index++
	return y

}

func (t *Twister) twist() {
	var lowerMask uint32 = 0x7FFFFFFF
	var upperMask uint32 = 0x80000000
	for i := 0; i < twisterLength; i++ {
		x := (t.x[i] & upperMask) | (t.x[(i+1)%twisterLength] & lowerMask)
		xA := x >> 1
		t.x[i] = t.x[(i+397)%twisterLength] ^ xA ^ ((x & 1) * 0x9908b0df)
	}
	t.index = 0
}
