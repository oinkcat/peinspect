package main

import (
    "os"
    "path"
    "fmt"
    "log"
    "./peformat"
)

func main() {
    if len(os.Args) > 1 {
        peFilePath := os.Args[1]
        info, err := pe.OpenExecutable(peFilePath)
        defer info.Close()
        
        if err == nil {
            fmt.Printf("Summary of %s:\n", path.Base(info.FileName))
            info.Inspect()
        } else {
            log.Fatal(err)
        }
    } else {
        log.Fatal("File path not specified!")
    }
}
