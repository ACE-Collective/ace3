package libautoit

type IDecompressor interface {
	Decompress() ([]byte, error)
	SetCallback(func(done, tot int))
}

func CreateDecompressor(ver AutoItVersion, inpBuf []byte, decompSize uint32) IDecompressor {
	if ver == EA06 {
		return NewEa06Decompressor(inpBuf, decompSize)
	} else if ver == EA05 {
		return NewEa05Decompressor(inpBuf, decompSize)
	} else {
		return NewLegacyDecompressor(inpBuf, decompSize)
	}
}
