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
        file, err := os.Open(peFilePath)
        defer file.Close()
        
        if err == nil {
            fmt.Printf("Summary of %s:\n", path.Base(peFilePath))
            info := pe.ParseFile(file)
            info.Inspect()
        } else {
            log.Fatal(err)
        }
    } else {
        log.Fatal("File path not specified!")
    }
}
