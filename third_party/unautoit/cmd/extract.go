/*
Copyright © 2020 x0r19x91

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
    "bytes"
    "errors"
    "fmt"
    "github.com/dustin/go-humanize"
    "github.com/gosuri/uiprogress"
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
    "github.com/x0r19x91/libautoit"
    "github.com/x0r19x91/libautoit/tidy"
    "io/ioutil"
    "log"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "time"
)

var id int
var outputDir string
var styleInfo string

type indentOptions struct {
    nSpaces            int
    useTabs            bool
    caseMap            tidy.IdentCase
    useEndFuncComments bool
    nMaxStrLitSize     int
    useExtraNewline    bool
}

func NewIndentOptions(rd string) *indentOptions {
    iop := &indentOptions{
        nSpaces:            4,
        useTabs:            false,
        caseMap:            tidy.AutoDetect,
        useEndFuncComments: true,
        nMaxStrLitSize:     160,
        useExtraNewline:    true,
    }
    data := make(map[string]string)
    for _, opt := range strings.Fields(rd) {
        tmp := strings.Split(opt, "=")
        data[tmp[0]] = tmp[1]
    }
    if val, ok := data["spaces"]; ok {
        if iVal, err := strconv.Atoi(val); err == nil {
            iop.nSpaces = iVal
        }
    }
    if val, ok := data["use-tabs"]; ok {
        iop.useTabs = strings.ToLower(val) == "on"
    }
    if val, ok := data["case-map"]; ok {
        switch strings.ToLower(val) {
        case "upper":
            iop.caseMap = tidy.AllUpper
        case "lower":
            iop.caseMap = tidy.AllLower
        default:
            iop.caseMap = tidy.AutoDetect
        }
    }
    if val, ok := data["auto-cmt"]; ok {
        iop.useEndFuncComments = strings.ToLower(val) == "on"
    }
    if val, ok := data["max-strsz"]; ok {
        if iVal, err := strconv.Atoi(val); err == nil {
            iop.nMaxStrLitSize = iVal
        }
    }
    if val, ok := data["extra-nl"]; ok {
        iop.useExtraNewline = strings.ToLower(val) == "on"
    }
    return iop
}

func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s took %s", name, elapsed)
}

func extractResource(fileName string) {
    // defer timeTrack(time.Now(), "extractResource")
    opts := NewIndentOptions(styleInfo)
    buffer, err := ioutil.ReadFile(fileName)
    if err != nil {
        fmt.Fprintf(os.Stderr, "[ Error ]: %s\n", err)
        return
    }
    au3File, err := libautoit.GetScripts(buffer)
    if err != nil {
        fmt.Fprintf(os.Stderr, "[ Error ]: %s\n", err)
        return
    }
    var res *libautoit.AutoItResource
    for i, r := range au3File.Resources {
        if i == id {
            res = r
            break
        }
    }
    if res == nil {
        fmt.Fprintf(os.Stderr,
            "[ Error ]: No such resource id. Try using list command",
        )
        return
    }
    if len(outputDir) == 0 {
        outputDir = "dump"
    }
    if _, err := os.Stat(outputDir); os.IsNotExist(err) {
        os.Mkdir(outputDir, 0755)
    }
    if !res.Decompress() {
        fmt.Fprintln(os.Stderr, "[ Error ]: Script is compressed. Decompressor failed")
        return
    }
    fileName = res.Name()
    if strings.HasPrefix(fileName, ">>>") {
        cat := strings.ReplaceAll(fileName, ">", "")
        cat = strings.ReplaceAll(cat, "<", "")
        cat = strings.ReplaceAll(cat, " ", "-")
        fileName = fmt.Sprintf("%s_%d.au3", cat, id)
        lexer := res.CreateTokenizer()
        cleaner := tidy.NewTidyInfo(lexer)
        cleaner.SetUseExtraNewline(opts.useExtraNewline)
        cleaner.SetUseTabs(opts.useTabs)
        cleaner.SetMaxStringLiteralSize(opts.nMaxStrLitSize)
        cleaner.SetIndentSpaces(opts.nSpaces)
        cleaner.SetIdentifierCase(opts.caseMap)
        cleaner.SetFuncComments(opts.useEndFuncComments)
        bar := uiprogress.AddBar(100).AppendCompleted().
            PrependFunc(func(b *uiprogress.Bar) string {
                return "Indenting " + fileName
            })
        bar.Width = 30
        buf := new(bytes.Buffer)
        cleaner.SetNotifyCallback(func(consumed, tot int) {
            bar.Set(consumed * 100 / tot)
        })
        uiprogress.Start()
        code := cleaner.Tidy()
        bar.Set(100)
        uiprogress.Stop()

        header := `
;
;    +--------------------------------------------------+
;    |   UnAutoIt - The Open Source AutoIt Decompiler   |
;    +--------------------------------------------------+
;
;    Generated on: %s
;

`
        buf.WriteString(fmt.Sprintf(header, time.Now().Format(time.RFC1123)))
        buf.WriteString(code)
        res.Data = buf.Bytes()
    }
    fileName = filepath.Join(outputDir, fileName)
    ioutil.WriteFile(fileName, res.Data, 0666)
    fmt.Printf("[*] Written %s to %q\n",
        humanize.Bytes(uint64(len(res.Data))), fileName)
}

// extractCmd represents the extract command
var extractCmd = &cobra.Command{
    Use: "extract file",
    Args: func(cmd *cobra.Command, args []string) error {
        if len(args) < 0 {
            return errors.New("requires a file: AutoItv3+ compiled binary")
        }
        if _, err := os.Stat(args[0]); os.IsNotExist(err) {
            return fmt.Errorf("%s does not exist", args[0])
        }
        return nil
    },
    Short: "Extract Resource using Id",
    Long:  `Selectively extract resources given id of the resource`,
    Run: func(cmd *cobra.Command, args []string) {
        if len(args) != 1 {
            _ = cmd.Help()
            return
        }
        extractResource(args[0])
    },
}

func init() {
    rootCmd.AddCommand(extractCmd)

    // Here you will define your flags and configuration settings.

    // Cobra supports Persistent Flags which will work for this command
    // and all subcommands, e.g.:
    // extractCmd.PersistentFlags().String("foo", "", "A help for foo")
    extractCmd.Flags().IntVar(&id, "id", 0,
        "Id of resource to extract")
    extractCmd.Flags().StringVarP(&outputDir, "output-dir",
        "o", "dump",
        "Directory to dump resources to (default $PWD/dump/)")
    extractCmd.Flags().StringVar(
        &styleInfo, "style", "", "Style Information",
    )
    extractCmd.Flags().Lookup("style").Usage =
        "Default: 'spaces=4 tabs=off case-map=auto auto-cmt=on strlit-max=160 extra-nl=on'"

    _ = extractCmd.MarkFlagRequired("id")
    _ = viper.BindPFlag("style", extractCmd.Flags().Lookup("style"))

    // Cobra supports local flags which will only run when this command
    // is called directly, e.g.:
    // extractCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
