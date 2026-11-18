package libautoit

import (
	"bytes"
	"github.com/x0r19x91/libautoit/lexer"
	"strings"
	"time"
)

type AutoItFile struct {
	Resources []*AutoItResource
	Version   AutoItVersion
}

func GetScripts(data []byte) (*AutoItFile, error) {
	temp := make([]byte, len(data))
	copy(temp, data)
	var pos []int
	for i := 0; i < 0x100; i++ {
		for j, v := range temp {
			data[j] = byte(i) ^ v
		}

		pos = []int{}
		startPos := -1
		for {
			// newPos := bytes.Index(temp[startPos+1:], Au3Header)
			// if newPos == -1 {
			//     break
			// }
			newPos := -1
			for _, hdr := range Au3Headers {
				idx := bytes.Index(temp[startPos+1:], hdr)
				if idx >= 0 {
					newPos = idx
					break
				}
			}
			if newPos == -1 {
				break
			}
			startPos += newPos + 1
			pos = append(pos, startPos)
		}

		if len(pos) > 0 {
			break
		}
	}

	if len(pos) == 0 {
		return nil, ErrScriptNotFound
	}

	startPos, endPos := 0, -1
	possibleScripts := make(map[int]int)
	var subtype string
	for _, p := range pos {
		startPos = p
		subtype = string(data[p+0x10 : p+0x18])
		if subtype[:4] != "AU3!" {
			continue
		}

		stop := bytes.LastIndex(data[p+0x19:], []byte(subtype))
		if stop == -1 {
			stop = len(data)
		} else {
			stop += p + 0x19
		}
		endPos = stop
		possibleScripts[p] = endPos
	}

	isLegacy := false
	if endPos == -1 && startPos > 0 {
		endPos = len(data) - 4
		if _, ok := possibleScripts[startPos]; !ok {
			possibleScripts[startPos] = endPos
		}
		isLegacy = true
		subtype = "AU3!OLD"
	}

	if len(possibleScripts) == 0 || len(subtype) == 0 {
		return nil, ErrScriptNotFound
	}

	file := new(AutoItFile)
	if subtype == "AU3!EA06" {
		file.Version = EA06
	} else if subtype == "AU3!EA05" {
		file.Version = EA05
	} else {
		file.Version = Legacy
	}
	for start, end := range possibleScripts {
		script := data[start:end]
		res, err := unpackResources(script, isLegacy, file.Version)
		if err != nil {
			return file, err
		}

		file.Resources = append(file.Resources, res...)
	}
	return file, nil
}

func unpackResources(script []byte, bLegacy bool, ver AutoItVersion) ([]*AutoItResource, error) {
	var iKeys IKeySet
	if ver == EA06 {
		iKeys = NewEA06()
	} else if ver == EA05 {
		iKeys = NewEA05()
	} else {
		// script[0x16] = 1 => MSVCRT
		//              = 3 => MT19937
		iKeys = NewLegacy(script[0x10] == 1)
	}
	// hash := iKeys.ForceDecodeStream(script[0x18:0x28], 0x99f2, false)
	iKeys.SetHash(script[0x18:0x28])
	pos := 0x28
	var isOldAutoIt bool
	if ver == Legacy {
		passLen := u32(script[0x11:0x15]) ^ 0xfac1
		pass := iKeys.DecodeStream(script[0x15:0x15+passLen], iKeys.GetPassKey())
		if !IsPrintable(pass) {
			isOldAutoIt = true
			//     iKeys = NewLegacy(true)
			//     pass = iKeys.DecodeStream(script[0x15:0x15+passLen], iKeys.GetPassKey())
		}
		iKeys.SetPassword(pass)
		// log.Printf("\nPassword: %s\n", string(pass))
		pos = 0x15 + int(passLen)
	}

	var ans []*AutoItResource
	for pos < len(script) {
		pFile := string(iKeys.DecodeStream(script[pos:pos+4], iKeys.GetFile()))
		if pFile != "FILE" {
			break
		}
		pos += 4 // "FILE"
		res := new(AutoItResource)
		res.KeySet = iKeys

		if pos >= len(script) {
			break
		}
		temp := int(u32(script[pos:pos+4])) ^ iKeys.GetTagSize().value
		pos += 4
		tagLen := temp
		if iKeys.NeedsUnicode() {
			tagLen += temp
		}
		res.Tag = iKeys.DecodeString(script[pos:pos+tagLen], iKeys.GetTag())
		pos += tagLen

		if pos >= len(script) {
			break
		}
		temp = int(u32(script[pos:pos+4])) ^ iKeys.GetPathSize().value
		pos += 4
		pathLen := temp
		if iKeys.NeedsUnicode() {
			pathLen += temp
		}
		res.Path = iKeys.DecodeString(script[pos:pos+pathLen], iKeys.GetPath())
		pos += pathLen

		res.IsCompressed = script[pos] != 0
		pos++

		if pos >= len(script) {
			break
		}
		temp = int(u32(script[pos:pos+4])) ^ iKeys.GetCompressedSize().value
		pos += 4
		res.CompressedSize = uint32(temp)
		if temp >= len(script) {
			return nil, ErrInvalidCompressedSize
		}

		if pos >= len(script) {
			break
		}
		temp = int(u32(script[pos:pos+4])) ^ iKeys.GetDecompressedSize().value
		pos += 4
		res.DecompressedSize = uint32(temp)

		if !bLegacy {
			temp = int(u32(script[pos:pos+4])) ^ iKeys.GetChecksum().value
			pos += 4
			res.Checksum = uint32(temp)
		}

		if !isOldAutoIt {
			nsec := int64(u32(script[pos:pos+4])) << 32
			nsec |= int64(u32(script[pos+4 : pos+8]))
			nsec -= 116444736000000000
			nsec *= 100
			res.CreationTime = time.Unix(0, nsec)
			pos += 8
			nsec = int64(u32(script[pos:pos+4])) << 32
			nsec |= int64(u32(script[pos+4 : pos+8]))
			nsec -= 116444736000000000
			nsec *= 100
			res.ModifiedTime = time.Unix(0, nsec)
			pos += 8
		}

		if res.CompressedSize > 0 {
			data := iKeys.DecodeStream(script[pos:pos+int(res.CompressedSize)], iKeys.GetData())
			res.Data = data
			pos += int(res.CompressedSize)
		}

		res.Decompressor = CreateDecompressor(ver, res.Data, res.DecompressedSize)
		res.State = Au3Initialized
		ans = append(ans, res)
	}
	return ans, nil
}

func (r *AutoItResource) IsAutoItScript(accuracy int) bool {
	var lex lexer.ITokenizer
	if IsPrintable(r.Data) {
		lex = lexer.NewTokenizer(r.Data)
	} else if strings.Contains(r.Tag, "SCRIPT") {
		lex = lexer.NewLexer(r.Data)
	}
	if lex == nil {
		return false
	}
	for {
		if accuracy == 0 {
			break
		}
		accuracy--
		tok := lex.NextToken()
		if tok.TokType == lexer.EOF {
			break
		}
		if tok.TokType == lexer.InvalidToken {
			return false
		}
	}
	return true
}

func (r *AutoItResource) Decompress() bool {
	if r.IsCompressed {
		buf, err := r.Decompressor.Decompress()
		if err != nil || (len(r.Data) > 0 && len(buf) == 0) {
			return false
		}
		r.State = Au3Decompressed
		r.Data = buf
	}
	if !IsPrintable(r.Data) {
		// see if utf16
		uBuf := []byte(FromUtf16(r.Data))
		if IsPrintable(uBuf) {
			r.Data = uBuf
		}
	}
	return true
}

func (r *AutoItResource) CreateTokenizer() lexer.ITokenizer {
	if IsPrintable(r.Data) {
		return lexer.NewTokenizer(r.Data)
	} else {
		return lexer.NewLexer(r.Data)
	}
}
