package libautoit

import "encoding/binary"

// Open Source Implementation of JB01 Decompressor
// from https://www.autoitscript.com/site/code/

const (
	Jb01Minmatchlen             = 3
	Jb01HuffLiteralAlphabetsize = 256 + 32
	Jb01HuffLiteralLenstart     = 256
	Jb01HuffOffsetAlphabetsize  = 32
	Jb01HuffLiteralInitialdelay = Jb01HuffLiteralAlphabetsize / 4
	Jb01HuffLiteralDelay        = Jb01HuffLiteralAlphabetsize * 12
	Jb01HuffOffsetInitialdelay  = Jb01HuffOffsetAlphabetsize / 4
	Jb01HuffOffsetDelay         = Jb01HuffOffsetAlphabetsize * 12
	Jb01HuffLiteralFreqmod      = 1
	Jb01HuffOffsetFreqmod       = 1
	Jb01HuffMaxcodebits         = 16
	Jb01DataSize                = 128 * 1024
	Jb01DataMask                = Jb01DataSize - 1
)

type huffmanDecompNode struct {
	nFrequency              uint64
	bSearchMe               bool
	nParent                 int
	nChildLeft, nChildRight uint32
	cValue                  byte
}

func huffmanZero(huffTree []huffmanDecompNode, nAlphabetSize int) {
	for i := 0; i < nAlphabetSize; i++ {
		huffTree[i].nFrequency = 1
		huffTree[i].nChildLeft = uint32(i)
		huffTree[i].nChildRight = uint32(i)
	}
}

type jb01Decomp struct {
	inputBuffer                []byte
	decompressedSize           int
	outputBuffer               []byte
	bData                      []byte
	outPos                     int
	inPos                      int
	nDataSize                  int
	nDataPos                   int
	nDataWritePos              int
	nDataUsed                  int
	nCompressedLong            uint32
	nCompressedBitsUsed        int
	nHuffmanLiteralsLeft       int
	bHuffmanLiteralFullyActive bool
	nHuffmanLiteralIncrement   int

	huffmanLiteralTree        []huffmanDecompNode
	huffmanOffsetTree         []huffmanDecompNode
	nHuffmanOffsetsLeft       int
	bHuffmanOffsetFullyActive bool
	nHuffmanOffsetIncrement   int
}

func (r *jb01Decomp) Decompress() ([]byte, error) {
	maxPos := r.decompressedSize
	_ = u32(r.inputBuffer[:4]) // JB01, JB00
	size := int(binary.BigEndian.Uint32(r.inputBuffer[4:8]))
	r.inPos = 8
	if size > maxPos {
		maxPos = size
		r.decompressedSize = size
		r.nDataSize = size
	}
	r.outputBuffer = make([]byte, r.decompressedSize)
	for r.nDataPos < r.decompressedSize {
		nTemp := r.compressedStreamReadLiteral()
		if nTemp < Jb01HuffLiteralLenstart {
			r.bData[r.nDataPos&Jb01DataMask] = byte(nTemp)
			r.nDataPos++
			r.nDataUsed++
		} else {
			nLen := Jb01Minmatchlen + r.compressedStreamReadLen(nTemp)
			nOffset := int(r.compressedStreamReadOffset())
			nTempPos := r.nDataPos - nOffset
			for nLen > 0 {
				nLen--
				r.bData[r.nDataPos&Jb01DataMask] = r.bData[nTempPos&Jb01DataMask]
				nTempPos++
				r.nDataPos++
				r.nDataUsed++
			}
		}
		for r.nDataWritePos < r.nDataPos {
			r.outputBuffer[r.outPos] = r.bData[r.nDataWritePos&Jb01DataMask]
			r.outPos++
			r.nDataWritePos++
		}
		r.nDataUsed = 0
	}
	return r.outputBuffer, nil
}

func (r *jb01Decomp) compressedStreamReadOffset() uint32 {
	nCode := r.compressedStreamReadHuffman(r.huffmanOffsetTree, Jb01HuffOffsetAlphabetsize)
	r.huffmanOffsetTree[nCode].nFrequency++
	var nValue uint32
	if nCode <= 3 {
		nValue = nCode
	} else {
		nCode -= 4
		nExtraBits := int(1 + (nCode >> 1))
		nMSBValue := uint32(1 << (1 + nExtraBits))
		nCode &= 1
		nValue = r.compressedStreamReadBits(nExtraBits)
		nValue += nMSBValue + (nCode << nExtraBits)
	}
	r.nHuffmanOffsetsLeft--
	if r.nHuffmanOffsetsLeft == 0 {
		if r.bHuffmanOffsetFullyActive {
			r.nHuffmanOffsetsLeft = Jb01HuffOffsetDelay
			huffmanGenerate(r.huffmanOffsetTree, Jb01HuffOffsetAlphabetsize, Jb01HuffOffsetFreqmod)
		} else {
			r.nHuffmanOffsetIncrement += Jb01HuffOffsetInitialdelay
			if r.nHuffmanOffsetIncrement >= Jb01HuffOffsetDelay {
				r.bHuffmanOffsetFullyActive = true
			}
			r.nHuffmanOffsetsLeft = Jb01HuffOffsetInitialdelay
			huffmanGenerate(r.huffmanOffsetTree, Jb01HuffOffsetAlphabetsize, 0)
		}
	}
	return nValue
}

func (r *jb01Decomp) compressedStreamReadLen(nCode uint32) uint32 {
	if nCode <= 263 {
		return nCode - 256
	} else {
		nCode -= 264
		nExtraBits := int(1 + (nCode >> 2))
		nMSBValue := uint32(1 << (nExtraBits + 2))
		nCode &= 3
		nValue := r.compressedStreamReadBits(nExtraBits)
		return nValue + nMSBValue + (nCode << nExtraBits)
	}
}

func (r *jb01Decomp) compressedStreamReadLiteral() uint32 {
	nLiteral := r.compressedStreamReadHuffman(r.huffmanLiteralTree, Jb01HuffLiteralAlphabetsize)
	r.huffmanLiteralTree[nLiteral].nFrequency++
	r.nHuffmanLiteralsLeft--
	if r.nHuffmanLiteralsLeft == 0 {
		if r.bHuffmanLiteralFullyActive {
			r.nHuffmanLiteralsLeft = Jb01HuffLiteralDelay
			huffmanGenerate(r.huffmanLiteralTree, Jb01HuffLiteralAlphabetsize, Jb01HuffLiteralFreqmod)
		} else {
			r.nHuffmanLiteralIncrement += Jb01HuffLiteralInitialdelay
			if r.nHuffmanLiteralIncrement >= Jb01HuffLiteralDelay {
				r.bHuffmanLiteralFullyActive = true
			}
			r.nHuffmanLiteralsLeft = Jb01HuffLiteralInitialdelay
			huffmanGenerate(r.huffmanLiteralTree, Jb01HuffLiteralAlphabetsize, 0)
		}
	}
	return nLiteral
}

func (r *jb01Decomp) compressedStreamReadHuffman(tree []huffmanDecompNode, nAlSize uint32) uint32 {
	nCode := 2*nAlSize - 2
	for nCode != tree[nCode].nChildLeft {
		nTemp := r.compressedStreamReadBits(1)
		if nTemp == 0 {
			nCode = tree[nCode].nChildLeft
		} else {
			nCode = tree[nCode].nChildRight
		}
	}
	return nCode
}

func (r *jb01Decomp) compressedStreamReadBits(nbits int) uint32 {
	r.nCompressedLong &= 0xffff
	for nbits > 0 {
		if r.nCompressedBitsUsed == 0 {
			r.nCompressedLong |= r.nextWord()
			r.nCompressedBitsUsed = 0x10
		}
		nbits--
		r.nCompressedLong <<= 1
		r.nCompressedBitsUsed--
	}
	return r.nCompressedLong >> 16
}

func (r *jb01Decomp) nextWord() uint32 {
	tmp := uint32(r.inputBuffer[r.inPos]) << 8
	tmp |= uint32(r.inputBuffer[r.inPos+1])
	r.inPos += 2
	return tmp
}

func (self *jb01Decomp) huffmanInit() {
	huffmanZero(self.huffmanLiteralTree, Jb01HuffLiteralAlphabetsize)
	huffmanGenerate(self.huffmanLiteralTree, Jb01HuffLiteralAlphabetsize, 0)
	self.bHuffmanLiteralFullyActive = false
	self.nHuffmanLiteralIncrement = Jb01HuffLiteralInitialdelay
	self.nHuffmanLiteralsLeft = self.nHuffmanLiteralIncrement

	huffmanZero(self.huffmanOffsetTree, Jb01HuffOffsetAlphabetsize)
	huffmanGenerate(self.huffmanOffsetTree, Jb01HuffOffsetAlphabetsize, 0)
	self.bHuffmanOffsetFullyActive = false
	self.nHuffmanOffsetIncrement = Jb01HuffOffsetInitialdelay
	self.nHuffmanOffsetsLeft = self.nHuffmanOffsetIncrement
}

func huffmanGenerate(tree []huffmanDecompNode, nAlphabetSize, nFreqMod int) {
	for i := 0; i < nAlphabetSize; i++ {
		tree[i].bSearchMe = true
	}
	var nByte1, nByte2 uint32
	nRoot := 2*nAlphabetSize - 2
	nNextBlankEntry := nAlphabetSize
	nEndNode := nRoot + 1
	for nNextBlankEntry != nEndNode {
		nByte1Freq, nByte2Freq := ^uint64(0), ^uint64(0)
		for i := 0; i < nNextBlankEntry; i++ {
			if tree[i].bSearchMe {
				if tree[i].nFrequency < nByte2Freq {
					if tree[i].nFrequency < nByte1Freq {
						nByte2 = nByte1
						nByte2Freq = nByte1Freq
						nByte1 = uint32(i)
						nByte1Freq = tree[i].nFrequency
					} else {
						nByte2 = uint32(i)
						nByte2Freq = tree[i].nFrequency
					}
				}
			}
		}

		tree[nByte1].bSearchMe = false
		tree[nByte2].bSearchMe = false
		tree[nNextBlankEntry].nFrequency = tree[nByte1].nFrequency + tree[nByte2].nFrequency
		tree[nNextBlankEntry].bSearchMe = true
		tree[nNextBlankEntry].nChildLeft = nByte1
		tree[nNextBlankEntry].nChildRight = nByte2
		tree[nByte1].nParent = nNextBlankEntry
		tree[nByte2].nParent = nNextBlankEntry
		tree[nByte1].cValue = 0
		tree[nByte2].cValue = 1

		nNextBlankEntry++
	}

	for i := 0; i < nAlphabetSize; i++ {
		j := 0
		nParent := i
		for nParent != nRoot {
			j++
			nParent = tree[nParent].nParent
		}

		if j > Jb01HuffMaxcodebits {
			for i := 0; i < nAlphabetSize; i++ {
				tree[i].nFrequency = (tree[i].nFrequency >> 2) + 1
			}

			huffmanGenerate(tree, nAlphabetSize, nFreqMod)
			return
		}
	}

	if nFreqMod != 0 {
		for i := 0; i < nAlphabetSize; i++ {
			tree[i].nFrequency = (tree[i].nFrequency >> nFreqMod) + 1
		}
	}
}

func NewJB01Decompressor(inpBuf []byte, decompSize int) *jb01Decomp {
	ans := &jb01Decomp{
		inputBuffer:        inpBuf,
		decompressedSize:   decompSize,
		huffmanLiteralTree: make([]huffmanDecompNode, 2*Jb01HuffLiteralAlphabetsize-1),
		huffmanOffsetTree:  make([]huffmanDecompNode, 2*Jb01HuffOffsetAlphabetsize-1),
		bData:              make([]byte, Jb01DataSize),
	}
	ans.huffmanInit()
	return ans
}
