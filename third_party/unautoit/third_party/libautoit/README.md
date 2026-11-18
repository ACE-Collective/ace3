# libautoit

libautoit is a library for extracting and cleaning AutoItv3+ encoded scripts.

* It supports a3x, exe, and even upx packed files.
* Cross Platform
* Has a builtin script beautifier
* Doesn't execute the target executable like `Exe2Aut`

## Installation

Assuming you have set up your Go environment according to the docs, just:

```bash
go get -u github.com/x0r19x91/libautoit
```

## To start writing code:

```go
func TestGetScripts(t *testing.T) {
    file := `C:\Users\x0r19x91\Desktop\libautoit\tests\Build.exe`
    data, err := ioutil.ReadFile(file)
    if err != nil {
        t.Error(err)
    }
    res, err := libautoit.GetScripts(data)
    if err != nil || len(res.Resources) == 0 {
        t.Error(err)
    }
    os.Mkdir("dump", 0666)
    for _, r := range res.Resources {
        t.Log(r)
        if !r.Decompress() {
            t.Errorf("Decompessor Failed.")
        }
        if r.IsAutoItScript(500) {
            r.Data = bytes.ReplaceAll(r.Data, []byte{13, 10}, []byte{10})
            lex := r.CreateTokenizer()
            tidyInfo := tidy.NewTidyInfo(lex)
            tidyInfo.SetFuncComments(true)
            tidyInfo.SetIdentifierCase(tidy.AutoDetect)
            tidyInfo.SetIndentSpaces(4)
            tidyInfo.SetMaxStringLiteralSize(160)
            tidyInfo.SetUseExtraNewline(true)
            tidyInfo.SetUseTabs(false)
            cleaned := tidyInfo.Tidy()
            r.Data = []byte(cleaned)
            t.Log("Cleaned")
        }
        ioutil.WriteFile("dump/"+clean(r.Path), r.Data, 0666)
        t.Logf("Writing %d bytes to %s\n", len(r.Data), filepath.Base(r.Path))
    }
}
```


## License
[GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/)