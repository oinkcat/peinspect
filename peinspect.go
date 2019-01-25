package main

import (
    "os"
    "log"
    "./peformat"
)

func main() {
    if len(os.Args) > 1 {
        peFilePath := os.Args[1]
        file, err := os.Open(peFilePath)
        defer file.Close()
        
        if err == nil  {
            pe.Inspect(file)
        } else {
            log.Fatal(err)
        }
    } else {
        log.Fatal("File path not specified!")
    }
}
