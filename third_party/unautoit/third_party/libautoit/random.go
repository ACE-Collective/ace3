package libautoit

import (
	"math"
	"math/bits"
)

type IRandom interface {
	SetSeed(seed uint32)
	Rand() uint32
}

type msvcRand struct {
	seed uint32
}

func NewMsvcRand() *msvcRand {
	return &msvcRand{}
}

func (rnd *msvcRand) SetSeed(seed uint32) {
	rnd.seed = seed
}

func (rnd *msvcRand) Rand() uint32 {
	rnd.seed = rnd.seed*0x343fd + 0x269ec3
	return (rnd.seed >> 16) & 0x7fff
}

type mt19937 struct {
	index, a, b int
	mt          []uint32
}

const (
	mtLowerMask = uint32(1<<31 - 1)
	mtUpperMask = ^mtLowerMask
)

func NewMTRand() *mt19937 {
	return &mt19937{
		index: 625,
		mt:    make([]uint32, 624),
	}
}

func (rnd *mt19937) SetSeed(seed uint32) {
	rnd.index = 624
	rnd.mt[0] = seed
	for i := 1; i < 624; i++ {
		rnd.mt[i] = (rnd.mt[i-1]^rnd.mt[i-1]>>30)*0x6C078965 + uint32(i)
	}
	rnd.a = 1
	rnd.b = 1
}

func (rnd *mt19937) twist() {
	for i := 0; i < 624; i++ {
		x := rnd.mt[i]&mtUpperMask + rnd.mt[(i+1)%624]&mtLowerMask
		xa := x >> 1
		if x%2 == 1 {
			xa ^= 0x9908B0DF
		}
		rnd.mt[i] = xa ^ rnd.mt[(i+397)%624]
	}
	rnd.index = 0
}

func (rnd *mt19937) rand() uint32 {
	if rnd.index >= 624 {
		rnd.twist()
	}
	y := rnd.mt[rnd.index]
	y = y ^ (y >> 11)
	y = y ^ ((y << 7) & 0x9D2C5680)
	y = y ^ ((y << 15) & 0xEFC60000)
	y = y ^ (y >> 18)
	rnd.index++
	return y
}

func (rnd *mt19937) Rand() uint32 {
	return rnd.rand() >> 1
}

type ea06Rand struct {
	a, b  int
	state []uint32
}

func NewEa06Rand() *ea06Rand {
	return &ea06Rand{state: make([]uint32, 17)}
}

func (r *ea06Rand) SetSeed(seed uint32) {
	for i := 0; i < 17; i++ {
		seed = 1 - seed*0x53a9b4fb
		r.state[i] = seed
	}
	r.a = 0
	r.b = 10
	for i := 0; i < 9; i++ {
		r.nextReal()
	}
}

func (r *ea06Rand) nextReal() float64 {
	val := bits.RotateLeft32(r.state[r.a], 9) + bits.RotateLeft32(r.state[r.b], 13)
	r.state[r.a] = val
	r.a = (r.a + 16) % 17
	r.b = (r.b + 16) % 17
	lo := uint64(val << 0x14)
	hi := uint64(0x3FF00000 | (val >> 12))
	return math.Float64frombits((hi<<32)|lo) - 1.0
}

func (r *ea06Rand) Rand() uint32 {
	r.nextReal()
	return uint32(256.0 * r.nextReal())
}
