package libautoit

type legacyDecompress struct {
	inputBuffer          []byte
	outputBuffer         []byte
	inPos, count, outPos int
	ans                  uint32
	decompressedSize     int
	callback             func(done, tot int)
	nPages, nLastPage    int
}

func (r *legacyDecompress) SetCallback(f func(done int, tot int)) {
	r.callback = f
}

func NewLegacyDecompressor(inpBuf []byte, decompSize uint32) *legacyDecompress {
	return &legacyDecompress{
		inputBuffer:      inpBuf,
		outputBuffer:     make([]byte, decompSize),
		inPos:            0,
		count:            0,
		outPos:           0,
		ans:              0,
		decompressedSize: int(decompSize),
		callback:         func(done, tot int) {},
	}
}

func (r *legacyDecompress) extractBits(nbits int) (uint32, error) {
	r.ans &= 0xffff
	for nbits > 0 {
		nbits--
		if r.count == 0 {
			tmp, err := r.nextByte()
			if err != nil {
				return ^uint32(0), err
			}
			a := uint32(tmp)
			tmp, err = r.nextByte()
			if err != nil {
				return ^uint32(0), err
			}
			b := uint32(tmp)
			r.ans |= (a << 8) | b
			r.count = 16
		}
		r.ans <<= 1
		r.count--
	}
	return r.ans >> 0x10, nil
}

func (r *legacyDecompress) customExtractBits() (uint32, error) {
	var ans uint32
	n, err := r.extractBits(2)
	if err != nil {
		return ^uint32(0), err
	}
	if n == 3 {
		ans = 3
		n, err = r.extractBits(3)
		if err != nil {
			return ^uint32(0), err
		}
		if n == 7 {
			ans = 10
			n, err = r.extractBits(5)
			if err != nil {
				return ^uint32(0), err
			}
			if n == 0x1f {
				ans = 0x29
				for {
					n, err = r.extractBits(8)
					if err != nil {
						return ^uint32(0), err
					}
					if n != 0xff {
						break
					}
					ans += 0xff
				}
			}
		}
	}
	return ans + n + 3, nil
}

func (r *legacyDecompress) nextByte() (byte, error) {
	if r.inPos >= len(r.inputBuffer) {
		return 0xff, ErrOutOfBounds
	}
	r.inPos++
	return r.inputBuffer[r.inPos-1], nil
}

func (l *legacyDecompress) Decompress() ([]byte, error) {
	if IsPrintable(l.inputBuffer) {
		return l.inputBuffer, nil
	} else {
		// Weird ...
		// old autoit uses JB01 format but different decompressor
		// so, let's try to decompress with the old decompressor
		// if it fails, try the new JB01 decompressor
		tmpBuf := make([]byte, len(l.inputBuffer))
		copy(tmpBuf, l.inputBuffer)
		// legacy versions of autoit
		out, err := l.LegacyDecompress()
		if err != nil {
			// latest Version of autoit
			jb0x := NewJB01Decompressor(tmpBuf, l.decompressedSize)
			return jb0x.Decompress()
		} else {
			return out, nil
		}
	}
}

func (l *legacyDecompress) LegacyDecompress() ([]byte, error) {
	_, err := l.extractBits(8)
	if err != nil {
		return nil, err
	}
	_, err = l.extractBits(8)
	if err != nil {
		return nil, err
	}
	_, err = l.extractBits(8)
	if err != nil {
		return nil, err
	}
	_, err = l.extractBits(8)
	if err != nil {
		return nil, err
	}
	tmp, err := l.extractBits(16)
	if err != nil {
		return nil, err
	}
	size := tmp << 16
	tmp, err = l.extractBits(16)
	if err != nil {
		return nil, err
	}
	size |= tmp

	l.nLastPage, l.nPages = 0, 0
	for l.outPos < l.decompressedSize {
		choice, err := l.extractBits(1)
		if err != nil {
			return nil, err
		}
		if choice == 0 {
			tmp, err = l.extractBits(8)
			if err != nil {
				return nil, err
			}
			l.outputBuffer[l.outPos] = byte(tmp)
			l.outPos++
		} else {
			tmp, err = l.extractBits(13)
			if err != nil {
				return nil, err
			}
			delta := l.outPos - 3 - int(tmp)
			tmp, err = l.extractBits(4)
			if err != nil {
				return nil, err
			}
			count := 3 + int(tmp)
			if (l.outPos+count >= l.decompressedSize) || (delta < 0) ||
				(delta+count > l.decompressedSize) {
				return nil, ErrDecompressFailed
			}
			copyOverlapping(l.outputBuffer[l.outPos:l.outPos+count], l.outputBuffer[delta:delta+count])
			l.outPos += count
		}
		l.nLastPage, l.nPages = l.nPages, l.outPos/4096
		if l.nPages != l.nLastPage {
			go l.callback(l.outPos, l.decompressedSize)
		}
	}

	return l.outputBuffer, nil
}
