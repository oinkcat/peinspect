package main

import (
    "os"
    "path"
    "fmt"
    "log"
    "flag"
    "./peformat"
)

var (
    flagAll bool
    flagBasicInfo bool
    flagSections bool
    flagImports bool
    flagExports bool
    flagHelp bool
)

type InfoPrinter func(*pe.PEInfo)

// Print program usage and available flags
func printUsage() {
    programName := path.Base(os.Args[0])
    fmt.Printf("Usage: %s <flags> <filepath>\nWhere flags are:\n", programName)
    flag.PrintDefaults()
}

// ...
func fillPrintersList(printers []InfoPrinter) []InfoPrinter {
    // Multiple info requested
    multipleInfo := false

    // Basic information
    basicPrinter := func(info *pe.PEInfo) {
        if multipleInfo {
            fmt.Println("Basic information:")
        }
        fmt.Println(info)
    }

    // PE sections
    sectionsPrinter := func(info *pe.PEInfo) {
        if multipleInfo {
            fmt.Println("Sections:")
        }
        for _, sectInfo := range(info.Sections) {
            fmt.Println(sectInfo)
        }
        fmt.Println()
    }

    // Imported functions
    importsPrinter := func(info *pe.PEInfo) {
        if multipleInfo {
            fmt.Println("Function imports:")
        }
        if len(info.Imports) > 0 {
            for _, importInfo := range(info.Imports) {
                fmt.Println(importInfo)
            }
        } else {
            fmt.Println("No imports!")
        }
    }

    // Exported functions
    exportsPrinter := func(info *pe.PEInfo) {
        if multipleInfo {
            fmt.Println("Function exports:")
        }
        if info.Exports.FunctionNames != nil {
            fmt.Println(info.Exports)
        } else {
            fmt.Println("No exports!")
        }
    }

    // Add printer functions for requested info

    allInfo := !(flagBasicInfo || flagSections || flagImports || flagExports)

    if flagBasicInfo || allInfo {
        printers = append(printers, basicPrinter)
    }
    if flagSections || allInfo {
        printers = append(printers, sectionsPrinter)
    }
    if flagImports || allInfo {
        printers = append(printers, importsPrinter)
    }
    if flagExports || allInfo {
        printers = append(printers, exportsPrinter)
    }

    if len(printers) > 1 {
        multipleInfo = true
    }

    return printers
}

func init() {
    flag.BoolVar(&flagAll,"A", true, "Print all info (default if no other flags)")
    flag.BoolVar(&flagBasicInfo,"B", false, "Print basic info")
    flag.BoolVar(&flagSections,"S", false, "Print sections")
    flag.BoolVar(&flagImports,"I", false, "Print imports")
    flag.BoolVar(&flagExports,"E", false, "Print exports")

    flag.BoolVar(&flagHelp,"help", false, "Display help message")
    
    flag.Parse()
}

func main() {
    flag.Parse()
    args := flag.Args()

    if !flagHelp {
        if len(args) > 0 {
            // Open and parse specified executable
            peFilePath := args[0]
            peInfo, err := pe.OpenExecutable(peFilePath)
            defer peInfo.Close()
            
            if err == nil {
                // Print requested info
                infoPrinters := make([]InfoPrinter, 0)
                infoPrinters = fillPrintersList(infoPrinters)
                
                for _, printer := range(infoPrinters) {
                    printer(peInfo)
                }
            } else {
                log.Fatal(err)
            }
        } else {
            log.Fatal("File path not specified!")
        }
    } else {
        // Help requested
        printUsage()
    }
}
