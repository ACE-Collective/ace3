package libautoit

import (
	"unicode/utf16"
)

type KValue struct {
	value       int
	needsAddLen bool
}

type KeySet struct {
	File                             KValue
	TagSize, Tag                     KValue
	PathSize, Path                   KValue
	CompressedSize, DecompressedSize KValue
	Checksum                         KValue
	Data                             KValue
	PassKey                          KValue
	version                          AutoItVersion
	Hash                             []byte
	IsUnicode, AddLen, IsLegacy      bool
	Password                         []byte
	generator                        IRandom
}

type IKeySet interface {
	DecodeStream(buf []byte, key KValue) []byte
	ForceDecodeStream(buf []byte, key int, bAdd bool) []byte
	DecodeString(buf []byte, key KValue) string
	GetFile() KValue
	GetTagSize() KValue
	GetTag() KValue
	GetPathSize() KValue
	GetPath() KValue
	GetCompressedSize() KValue
	GetDecompressedSize() KValue
	GetChecksum() KValue
	GetData() KValue
	GetPassKey() KValue
	GetHash() []byte
	NeedsUnicode() bool
	NeedsAddLen() bool
	NeedsLegacy() bool
	GetGenerator() IRandom
	SetPassword(pass []byte)
	SetHash(hash []byte)
}

func (k *KeySet) GetHash() []byte {
	return k.Hash
}

func (k *KeySet) GetFile() KValue {
	return k.File
}

func (k *KeySet) SetPassword(pass []byte) {
	k.Password = pass
}

func (k *KeySet) SetHash(hash []byte) {
	k.Hash = hash
}

func (k *KeySet) GetPassKey() KValue {
	return k.PassKey
}

func (k *KeySet) GetTagSize() KValue {
	return k.TagSize
}

func (k *KeySet) GetTag() KValue {
	return k.Tag
}

func (k *KeySet) GetPathSize() KValue {
	return k.PathSize
}

func (k *KeySet) GetPath() KValue {
	return k.Path
}

func (k *KeySet) GetCompressedSize() KValue {
	return k.CompressedSize
}

func (k *KeySet) GetDecompressedSize() KValue {
	return k.DecompressedSize
}

func (k *KeySet) GetChecksum() KValue {
	return k.Checksum
}

func (k *KeySet) GetData() KValue {
	if k.version == EA05 {
		ans := uint32(k.Data.value)
		for _, r := range k.Hash {
			ans += uint32(uint8(r))
		}
		return KValue{
			value:       int(ans),
			needsAddLen: k.Data.needsAddLen,
		}
	}
	if k.NeedsLegacy() {
		ans := -0x849 // not needed for legacy
		ans += k.Data.value
		for _, r := range k.Password {
			ans += int(int8(r))
		}
		return KValue{
			value:       ans,
			needsAddLen: k.Data.needsAddLen,
		}
	} else {
		return k.Data
	}
}

func (k *KeySet) NeedsUnicode() bool {
	return k.IsUnicode
}

func (k *KeySet) NeedsAddLen() bool {
	return k.AddLen
}

func (k *KeySet) NeedsLegacy() bool {
	return k.IsLegacy
}

func (k *KeySet) GetGenerator() IRandom {
	return k.generator
}

type ea06 struct {
	KeySet
}

type ea05 struct {
	KeySet
}

func (e *ea05) DecodeStream(buf []byte, key KValue) []byte {
	return e.ForceDecodeStream(buf, key.value, key.needsAddLen)
}

func (e *ea05) ForceDecodeStream(buf []byte, key int, bAdd bool) []byte {
	factor := 1
	if e.NeedsUnicode() {
		factor++
	}
	if bAdd {
		key += len(buf) / factor
	}
	e.generator.SetSeed(uint32(key))
	ans := make([]byte, len(buf))
	for i := 0; i < len(buf); i++ {
		ans[i] = buf[i] ^ byte(e.generator.Rand())
	}
	return ans
}

func (r *ea05) DecodeString(buf []byte, key KValue) string {
	ans := r.DecodeStream(buf, key)
	if r.IsUnicode {
		u16arr := make([]uint16, len(ans)/2)
		for i := 0; i < len(ans); i += 2 {
			t := (uint16(ans[i+1]) << 8) | uint16(ans[i])
			u16arr[i/2] = t
		}
		return string(utf16.Decode(u16arr))
	} else {
		return string(ans)
	}
}

type legacy struct {
	ea05
	oldAutoIt bool
}

func (l *legacy) ForceDecodeStream(buf []byte, key int, bAdd bool) []byte {
	if bAdd {
		key += len(buf)
	} else {
		key += 0x849
	}
	l.generator.SetSeed(uint32(key))
	ans := make([]byte, len(buf))
	for i, r := range buf {
		ans[i] = r ^ byte(l.generator.Rand())
	}
	return ans
}

func (l *legacy) DecodeStream(buf []byte, key KValue) []byte {
	return l.ForceDecodeStream(buf, key.value, key.needsAddLen)
}

func (r *legacy) DecodeString(buf []byte, key KValue) string {
	ans := r.DecodeStream(buf, key)
	if r.IsUnicode {
		u16arr := make([]uint16, len(ans)/2)
		for i := 0; i < len(ans); i += 2 {
			t := (uint16(ans[i+1]) << 8) | uint16(ans[i])
			u16arr[i/2] = t
		}
		return string(utf16.Decode(u16arr))
	} else {
		return string(ans)
	}
}

func NewEA06() *ea06 {
	return &ea06{
		KeySet{
			File:             KValue{value: 0x18ee, needsAddLen: false},
			TagSize:          KValue{value: 0xadbc, needsAddLen: true},
			Tag:              KValue{value: 0xb33f, needsAddLen: true},
			PathSize:         KValue{value: 0xf820, needsAddLen: true},
			Path:             KValue{value: 0xf479, needsAddLen: true},
			CompressedSize:   KValue{value: 0x87bc, needsAddLen: true},
			DecompressedSize: KValue{value: 0x87bc, needsAddLen: true},
			Checksum:         KValue{value: 0xa685, needsAddLen: true},
			Data:             KValue{value: 0x2477, needsAddLen: false},
			PassKey:          KValue{value: 0xc3d2, needsAddLen: false},
			IsUnicode:        true,
			AddLen:           true,
			version:          EA06,
			generator:        NewEa06Rand(),
		},
	}
}

func NewEA05() *ea05 {
	return &ea05{KeySet{
		File:             KValue{value: 0x16FA, needsAddLen: false},
		TagSize:          KValue{value: 0x29bc, needsAddLen: true},
		Tag:              KValue{value: 0xa25e, needsAddLen: true},
		PathSize:         KValue{value: 0x29ac, needsAddLen: true},
		Path:             KValue{value: 0xf25e, needsAddLen: true},
		CompressedSize:   KValue{value: 0x45aa, needsAddLen: true},
		DecompressedSize: KValue{value: 0x45aa, needsAddLen: true},
		Checksum:         KValue{value: 0xc3d2, needsAddLen: true},
		Data:             KValue{value: 0x22af, needsAddLen: false},
		PassKey:          KValue{value: 0xc3d2, needsAddLen: false},
		IsUnicode:        false,
		AddLen:           false,
		version:          EA05,
		generator:        NewMTRand(),
	}}
}

func NewLegacy(isOld bool) *legacy {
	var rndGen IRandom
	if isOld {
		rndGen = NewMsvcRand()
	} else {
		rndGen = NewMTRand()
	}
	return &legacy{
		ea05: ea05{KeySet{
			File:             KValue{value: 0x16FA - 0x849, needsAddLen: false},
			TagSize:          KValue{value: 0x29bc, needsAddLen: true},
			Tag:              KValue{value: 0xa25e, needsAddLen: true},
			PathSize:         KValue{value: 0x29ac, needsAddLen: true},
			Path:             KValue{value: 0xf25e, needsAddLen: true},
			CompressedSize:   KValue{value: 0x45aa, needsAddLen: true},
			DecompressedSize: KValue{value: 0x45aa, needsAddLen: true},
			Checksum:         KValue{value: 0xc3d2, needsAddLen: true},
			Data:             KValue{value: 0x22af, needsAddLen: false},
			PassKey:          KValue{value: 0xc3d2, needsAddLen: true},
			IsUnicode:        false,
			AddLen:           false,
			version:          Legacy,
			IsLegacy:         true,
			generator:        rndGen,
		}},
		oldAutoIt: isOld,
	}
}

func (l *legacy) SetIsLegacy(isLegacy bool) {
	l.oldAutoIt = isLegacy
	if isLegacy {
		l.generator = NewMsvcRand()
	} else {
		l.generator = NewMTRand()
	}
}

func (r *ea06) ForceDecodeStream(buf []byte, key int, bAdd bool) []byte {
	seed := key
	factor := 2
	if !r.NeedsUnicode() {
		factor--
	}
	if bAdd {
		seed += len(buf) / factor
	}
	r.generator.SetSeed(uint32(seed))
	ans := make([]byte, len(buf))
	for i := 0; i < len(buf); i++ {
		ans[i] = buf[i] ^ byte(r.generator.Rand())
	}
	return ans
}

func (r *ea06) DecodeStream(buf []byte, key KValue) []byte {
	return r.ForceDecodeStream(buf, key.value, key.needsAddLen)
}

func (r *ea06) DecodeString(buf []byte, key KValue) string {
	ans := r.DecodeStream(buf, key)
	if r.IsUnicode {
		u16arr := make([]uint16, len(ans)/2)
		for i := 0; i < len(ans); i += 2 {
			t := (uint16(ans[i+1]) << 8) | uint16(ans[i])
			u16arr[i/2] = t
		}
		return string(utf16.Decode(u16arr))
	} else {
		return string(ans)
	}
}
