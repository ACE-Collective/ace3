package libautoit

import (
	"fmt"
	"strings"
	"time"
)

type AutoItState int

const (
	Au3Initialized AutoItState = iota
	Au3Decompressed
	Au3Decompiled
	Au3Indented
)

type AutoItVersion int

func (a AutoItVersion) String() string {
	if a == EA06 {
		return "AU3.EA06"
	} else if a == EA05 {
		return "AU3.EA05"
	} else {
		return "Legacy" // maybe AutoHotKey also!
	}
}

const (
	EA06 AutoItVersion = iota
	EA05
	Legacy
)

type AutoItResource struct {
	// exported fields
	Tag              string // name of the resource
	Path             string // path where the resource was placed while compiling
	IsCompressed     bool
	CompressedSize   uint32 // if compressed, size of compressed resource
	DecompressedSize uint32 // size of decompressed resource
	Checksum         uint32
	CreationTime     time.Time // creation time
	ModifiedTime     time.Time // last write time
	Data             []byte    // raw data
	State            AutoItState
	Decompressor     IDecompressor
	KeySet           IKeySet
}

func (res *AutoItResource) Name() string {
	pos := strings.LastIndexByte(res.Tag, '\\')
	if pos == -1 {
		return res.Tag
	}
	return res.Tag[pos+1:]
}

func (r *AutoItResource) String() string {
	ans := fmt.Sprintf("Name: %60s\n", r.Name())
	ans += fmt.Sprintf("Path: %60s\n", r.Path)
	ans += fmt.Sprintf("Compressed Size: %60d bytes\n", r.CompressedSize)
	ans += fmt.Sprintf("Decompressed Size: %60d bytes\n", r.DecompressedSize)
	ans += fmt.Sprintf("Created at: %s\n", r.CreationTime.Format(time.ANSIC))
	ans += fmt.Sprintf("Modified at: %s\n", r.ModifiedTime.Format(time.ANSIC))
	return ans
}
