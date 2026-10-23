package libautoit

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

var (
	Au3HeaderEA06 = []byte{0xa3, 0x48, 0x4b, 0xbe, 0x98, 0x6c, 0x4a, 0xa9, 0x99, 0x4c, 0x53, 0xa, 0x86, 0xd6, 0x48, 0x7d}
	Au3HeaderEA05 = []byte{0xa3, 0x48, 0x4b, 0xbe, 0x98, 0x6c, 0xa9, 0x4a, 0x99, 0x4c, 0x53, 0x0a, 0x86, 0xd6, 0x48, 0x7d}
)
var Au3Headers = [][]byte{
	Au3HeaderEA06, Au3HeaderEA05,
}

const (
	PRINTABLE = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c"
)

type Au3Error int

const (
	ScriptNotFound = iota
	DecompressFailed
	InvalidSignature
	InvalidCompressedSize
	OutOfBounds
)

var errMap = map[Au3Error]string{
	ScriptNotFound:        "Script not Found.",
	DecompressFailed:      "Decompress Failed.",
	InvalidSignature:      "Invalid Signature in Compressed Data.",
	InvalidCompressedSize: "Invalid Compressed Size.",
	OutOfBounds:           "Index out of Bounds.",
}

var (
	ErrScriptNotFound        = &autoItError{err: ScriptNotFound}
	ErrDecompressFailed      = &autoItError{err: DecompressFailed}
	ErrInvalidSignature      = &autoItError{err: InvalidSignature}
	ErrInvalidCompressedSize = &autoItError{err: InvalidCompressedSize}
	ErrOutOfBounds           = &autoItError{err: OutOfBounds}
)

type autoItError struct {
	err Au3Error
}

func (er *autoItError) Error() string {
	if val, ok := errMap[er.err]; ok {
		return val
	} else {
		return "Unknown Error!"
	}
}

func u32(data []byte) uint32 {
	return binary.LittleEndian.Uint32(data)
}

func u64(data []byte) uint64 {
	return binary.LittleEndian.Uint64(data)
}

func IsPrintable(buf []byte) bool {
	for _, r := range buf {
		if strings.IndexByte(PRINTABLE, r) == -1 {
			return false
		}
	}
	return len(buf) > 0
}

// copy() doesn't copy overlapping slices
// copyOverlapping:
// dst and src can point to same underlying array
// works fine...
func copyOverlapping(dst, src []byte) {
	for i, b := range src {
		dst[i] = b
	}
}

func FromUtf16(data []byte) string {
	u16 := make([]uint16, len(data)/2)
	for i := 0; i < len(data)-1; i += 2 {
		u16[i/2] = uint16(data[i+1])<<8 | uint16(data[i])
	}
	return string(utf16.Decode(u16))
}
