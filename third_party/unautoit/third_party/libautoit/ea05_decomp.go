package libautoit

import "encoding/binary"

type ea05Decompress struct {
	inputBuffer          []byte
	outputBuffer         []byte
	inPos, count, outPos int
	ans                  uint32
	compressedSize       uint32
	decompressedSize     int
	callback             func(done, tot int)
	nPages, nLastPage    int
}

func (r *ea05Decompress) SetCallback(f func(done, tot int)) {
	r.callback = f
}

func (r *ea05Decompress) nextByte() byte {
	r.inPos++
	return r.inputBuffer[r.inPos-1]
}

func (r *ea05Decompress) extractBits(nbits int) uint32 {
	r.ans &= 0xffff
	for nbits > 0 {
		nbits--
		if r.count == 0 {
			a := uint32(r.nextByte())
			b := uint32(r.nextByte())
			r.ans |= (a << 8) | b
			r.count = 16
		}
		r.ans <<= 1
		r.count--
	}
	return r.ans >> 0x10
}

func (r *ea05Decompress) customExtractBits() uint32 {
	var ans uint32
	n := r.extractBits(2)
	if n == 3 {
		ans = 3
		n = r.extractBits(3)
		if n == 7 {
			ans = 10
			n = r.extractBits(5)
			if n == 0x1f {
				ans = 0x29
				for {
					n = r.extractBits(8)
					if n != 0xff {
						break
					}
					ans += 0xff
				}
			}
		}
	}
	return ans + n + 3
}

func (r *ea05Decompress) Decompress() ([]byte, error) {
	signature := string(r.inputBuffer[:4])
	size := int(binary.BigEndian.Uint32(r.inputBuffer[4:8]))
	if r.decompressedSize < size {
		r.outputBuffer = nil
		r.decompressedSize = size
		r.outputBuffer = make([]byte, size)
	}
	r.inPos = 8
	if signature != "EA05" {
		return nil, ErrInvalidSignature
	}
	r.nPages, r.nLastPage = 0, 0
	for r.outPos < r.decompressedSize {
		bits := r.extractBits(1)
		if bits == 0 {
			r.outputBuffer[r.outPos] = byte(r.extractBits(8))
			r.outPos++
		} else {
			v := int(r.extractBits(0xf))
			t := int(r.customExtractBits())
			delta := r.outPos - v
			copyOverlapping(r.outputBuffer[r.outPos:r.outPos+t], r.outputBuffer[delta:delta+t])
			r.outPos += t
		}
		r.nLastPage, r.nPages = r.nPages, r.outPos/4096
		if r.nPages != r.nLastPage {
			go r.callback(r.outPos, r.decompressedSize)
		}
	}

	return r.outputBuffer, nil
}

func NewEa05Decompressor(inpBuf []byte, decompSize uint32) *ea05Decompress {
	return &ea05Decompress{
		inputBuffer:      inpBuf,
		outputBuffer:     make([]byte, decompSize),
		inPos:            0,
		ans:              0,
		count:            0,
		outPos:           0,
		callback:         func(done, tot int) {},
		decompressedSize: int(decompSize),
	}
}
