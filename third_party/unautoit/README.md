![Github stats](https://img.shields.io/github/downloads/digitalsleuth/UnAutoIt/total.svg?style=for-the-badge&color=red)
![Licence](https://img.shields.io/badge/license-GPLv3-blue.svg?style=for-the-badge)  
![MadeWithGo](https://forthebadge.com/images/badges/made-with-go.svg)

# UnAutoIt

The Cross Platform AutoIt extractor

* Supports AutoItv3+
* Indents scripts
* Does not execute the target binary
* Extracts from UPX packed binaries

## How to Use

> List Resources

1. List Resources (Table)  
    `./unautoit list target-file.bin`

2. List Resources (JSON)  
    `./unautoit list target-file.bin --json`

3. Extract one resource  
    `./unautoit extract --id N [--output-dir out] target-file.bin`  
    where `N` is the id of the resource to extract.  
    If `out` is given the extracted resource is placed in the directory specified by `out`.  
    The default value of `out` is `$PWD/dump`

4. Extract all resources  
    `./unautoit extract-all [--output-dir out] target-file.bin`  
    If `out` is given the extracted resource is placed in the directory specified by `out`.  
    The default value of `out` is `$PWD/dump`


[![asciicast](https://asciinema.org/a/368551.svg)](https://asciinema.org/a/368551)
