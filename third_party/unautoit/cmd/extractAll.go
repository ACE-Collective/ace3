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
    "fmt"
    "github.com/gosuri/uiprogress"
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
    "github.com/x0r19x91/libautoit"
    "github.com/x0r19x91/libautoit/tidy"
    "io/ioutil"
    "os"
    "path/filepath"
    "sync"
)

type RInfo struct {
    *libautoit.AutoItResource
    bar    *uiprogress.Bar
    id     int
    state  string
    worker func(info *RInfo, wg *sync.WaitGroup)
}

// extractAllCmd represents the extractAll command
var extractAllCmd = &cobra.Command{
    Use:   "extract-all",
    Short: "Extract all resources from the AutoIt compiled binary",
    Long:  `Extract all resources from the AutoIt compiled binary`,
    Run: func(cmd *cobra.Command, args []string) {
        if len(args) != 1 {
            _ = cmd.Help()
            return
        }
        extractAll(args[0])
    },
}

func extractAll(fileName string) {
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

    if _, err := os.Stat(outputDir); os.IsNotExist(err) {
        os.Mkdir(outputDir, 0755)
    }
    var sg sync.WaitGroup
    // comm := make(chan bool)
    var argp []*RInfo
    uiprogress.Start()
    for id, rx := range au3File.Resources {
        tmp := &RInfo{
            AutoItResource: rx,
            bar:            nil,
            id:             id,
        }
        tmp.worker = func(r *RInfo, wg *sync.WaitGroup) {
            r.state = "Extracted"
            r.bar = uiprogress.AddBar(100).AppendCompleted().PrependFunc(
                func(b *uiprogress.Bar) string {
                    return r.Name()
                }).AppendFunc(
                func(b *uiprogress.Bar) string {
                    return r.state
                })
            r.bar.Width = 20
            r.state = "Decompressing"
            // r.Decompress()
            if r.IsCompressed {
                r.Decompressor.SetCallback(func(done, tot int) {
                    r.bar.Set(done * 100 / tot)
                })
                buf, _ := r.Decompressor.Decompress()
                r.Data = buf
                r.bar.Set(100)
            }
            if !libautoit.IsPrintable(r.Data) {
                // see if utf16
                uBuf := []byte(libautoit.FromUtf16(r.Data))
                if libautoit.IsPrintable(uBuf) {
                    r.Data = uBuf
                }
            }
            r.state = "Decompressed"
            fp := r.Name()
            if r.IsAutoItScript(20) {
                fp = fmt.Sprintf("script_%d.au3", r.id)
                info := NewIndentOptions(styleInfo)
                tidyTool := tidy.NewTidyInfo(r.CreateTokenizer())
                tidyTool.SetNotifyCallback(func(consumed, tot int) {
                    r.bar.Set(consumed * 100 / tot)
                })
                tidyTool.SetFuncComments(info.useEndFuncComments)
                tidyTool.SetIdentifierCase(info.caseMap)
                tidyTool.SetIndentSpaces(info.nSpaces)
                tidyTool.SetMaxStringLiteralSize(info.nMaxStrLitSize)
                tidyTool.SetUseTabs(info.useTabs)
                tidyTool.SetUseExtraNewline(info.useExtraNewline)
                r.state = "Decompiling"
                src := tidyTool.Tidy()
                r.state = "Indented"
                r.State = libautoit.Au3Decompiled
                r.Data = []byte(src)
            }
            r.bar.Set(100)
            r.state = "Dumping"
            ioutil.WriteFile(filepath.Join(outputDir, fp), r.Data, 0666)
            r.state = "Complete"
            wg.Done()
        }
        argp = append(argp, tmp)
    }

    sg.Add(len(argp))
    for _, r := range argp {
        go r.worker(r, &sg)
    }
    sg.Wait()
    uiprogress.Stop()
}

func init() {
    rootCmd.AddCommand(extractAllCmd)

    extractAllCmd.Flags().StringVarP(&outputDir, "output-dir",
        "o", "dump",
        "Directory to dump resources to (default $PWD/dump/)")
    extractAllCmd.Flags().StringVar(
        &styleInfo, "style", "", "Style Information",
    )
    extractAllCmd.Flags().Lookup("style").Usage =
        "Default: 'spaces=4 tabs=off case-map=auto auto-cmt=on strlit-max=160 extra-nl=on'"
    _ = viper.BindPFlag("style", extractAllCmd.Flags().Lookup("style"))
}
