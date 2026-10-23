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
    "encoding/json"
    "fmt"
    "github.com/dustin/go-humanize"
    "github.com/h2non/filetype"
    "github.com/olekukonko/tablewriter"
    "github.com/spf13/cobra"
    "github.com/x0r19x91/libautoit"
    "io/ioutil"
    "os"
    "strconv"
    "time"
)

var isJson bool

type Au3JsonInfo struct {
    Id               int       `json:"id"`
    Name             string    `json:"name"`
    Path             string    `json:"path"`
    Type             string    `json:"file_type""`
    IsCompressed     bool      `json:"is_compressed"`
    CompressedSize   uint32    `json:"compressed_size"`
    DecompressedSize uint32    `json:"decompressed_size"`
    CreationTime     time.Time `json:"creation_time"`
    ModifiedTime     time.Time `json:"modified_time"`
}

// listCmd represents the list command
var listCmd = &cobra.Command{
    Use:   "list file",
    Short: "List Resources embedded in the AutoIt compiled binary",
    Long:  `List Resources embedded in the AutoIt compiled binary`,
    Run: func(cmd *cobra.Command, args []string) {
        if len(args) != 1 {
            _ = cmd.Help()
            return
        }
        listResources(args[0])
    },
}

func listResources(fileName string) {
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
    var jsArray []*Au3JsonInfo
    for i, r := range au3File.Resources {
        mimeType := "unknown"
        if len(r.Data) == 0 {
            mimeType = "Empty File"
        } else if r.Decompress() {
            fType, _ := filetype.Match(r.Data)
            if fType != filetype.Unknown {
                mimeType = fType.MIME.Value
            } else {
                if r.IsAutoItScript(20) {
                    mimeType = "AutoIt Script"
                }
            }
        }
        jsArray = append(jsArray, &Au3JsonInfo{
            Id:               i,
            Name:             r.Name(),
            Path:             r.Path,
            IsCompressed:     r.IsCompressed,
            CompressedSize:   r.CompressedSize,
            DecompressedSize: r.DecompressedSize,
            CreationTime:     r.CreationTime,
            ModifiedTime:     r.ModifiedTime,
            Type:             mimeType,
        })
    }
    if isJson {
        buffer := new(bytes.Buffer)
        encoder := json.NewEncoder(buffer)
        encoder.SetEscapeHTML(false)
        encoder.SetIndent("", "    ")
        _ = encoder.Encode(jsArray)
        fmt.Printf("%s\n", buffer.String())
    } else {
        table := tablewriter.NewWriter(os.Stdout)
        table.SetHeader([]string{"Id", "Name", "Path", "Size", "Type"})
        for _, r := range jsArray {
            table.Append([]string{
                strconv.Itoa(r.Id), r.Name, r.Path,
                humanize.Bytes(uint64(r.DecompressedSize)),
                r.Type,
            })
        }
        table.Render()
    }
}

func init() {
    rootCmd.AddCommand(listCmd)

    // Here you will define your flags and configuration settings.

    // Cobra supports Persistent Flags which will work for this command
    // and all subcommands, e.g.:
    listCmd.Flags().BoolVar(&isJson, "json", false,
        "Display in JSON format")

    // Cobra supports local flags which will only run when this command
    // is called directly, e.g.:
    // listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
