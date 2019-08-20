package main

import (
    "os"
    "path"
    "fmt"
    "log"
    "flag"
    "./peformat"
)

const (
    ACTION_INFO = "info"
    ACTION_DUMP = "dump"
    ACTION_EXTRACT = "extract"
    ACTION_INVALID = "_invalid_"
)

var (
    flagAction string
    flagAll bool
    flagBasicInfo bool
    flagSections bool
    flagImports bool
    flagExports bool
    flagResources bool
    flagHelp bool
)

type InfoPrinter func(*pe.PEInfo)

// Print program usage and available flags
func printUsage() {
    programName := path.Base(os.Args[0])
    fmt.Printf("Usage: %s <flags> <filepath>\nWhere flags are:\n", programName)
    flag.PrintDefaults()
}

// Get list with requested info output functions
func getPrintersList() []InfoPrinter {
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

    // Resources
    resourcesPrinter := func(info *pe.PEInfo) {
        if multipleInfo {
            fmt.Println("\nResources:")
        }
        if info.Resources != nil {
            for _, resInfo := range(info.Resources) {
                fmt.Println(resInfo)
            }
        } else {
            fmt.Println("No resources!")
        }
    }

    // Add printer functions for requested info

    allInfo := !(flagBasicInfo || flagSections || 
                 flagImports || flagExports || 
                 flagResources)

    printers := []InfoPrinter {}

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
    if flagResources || allInfo {
        printers = append(printers, resourcesPrinter)
    }

    if len(printers) > 1 {
        multipleInfo = true
    }

    return printers
}

// Print requested information to stdout
func performInfoOutput(peInfo *pe.PEInfo) {
    // Print requested info
    infoPrinters := getPrintersList()
    
    for _, printer := range(infoPrinters) {
        printer(peInfo)
    }
}

// Dump section contents to file
func performSectionDump(peInfo *pe.PEInfo, name string, fileName string) {
    var sectionToDump pe.PESectionInfo

    // Find requested section
    for _, section := range(peInfo.Sections) {
        if section.Name == name {
            sectionToDump = section
            break
        }
    }

    // Dump contents
    if sectionToDump.Size != 0 {
        outFile, err := os.Create(fileName)
        defer outFile.Close()
        if err == nil {
            peInfo.DumpSection(sectionToDump, outFile)
            fmt.Printf("Section %s saved to %s\n", name, fileName)
        }
    } else {
        fmt.Printf("Section %s not found!\n", name)
    }
}

// Extract resource by it's path
func performResourceExtract(peInfo *pe.PEInfo, path string, fileName string) {
    var resourceToExtract pe.PEResource

    // Find resource
    for _, resInfo := range(peInfo.Resources) {
        if path == resInfo.Id {
            resourceToExtract = resInfo
            break
        }
    }

    // Extract resource
    if resourceToExtract.Size != 0 {
        outFile, err := os.Create(fileName)
        defer outFile.Close()
        if err == nil {
            peInfo.DumpResourceData(resourceToExtract, outFile)
            fmt.Printf("Resource %s saved to %s\n", path, fileName)
        }
    } else {
        fmt.Printf("Resource %s not found!\n", path)
    }
}

// Get action or nil if wrong action specified
func getRequestedAction() string {
    if flagAction == ACTION_INFO || 
       flagAction == ACTION_DUMP || 
       flagAction == ACTION_EXTRACT {
        return flagAction
    } else {
        return ACTION_INVALID
    }
}

func init() {
    flag.Usage = printUsage

    flag.StringVar(&flagAction, "action", ACTION_INFO, 
        fmt.Sprintf("requested action (%s - default, %s, %s)",
                    ACTION_INFO, ACTION_DUMP, ACTION_EXTRACT))
    flag.BoolVar(&flagAll,"A", true, "Print all info (default if no other flags)")
    flag.BoolVar(&flagBasicInfo,"B", false, "Print basic info")
    flag.BoolVar(&flagSections,"S", false, "Print sections")
    flag.BoolVar(&flagImports,"I", false, "Print imports")
    flag.BoolVar(&flagExports,"E", false, "Print exports")
    flag.BoolVar(&flagResources,"R", false, "Print resources")

    flag.BoolVar(&flagHelp,"help", false, "Display help message")
    
    flag.Parse()
}

func main() {
    flag.Parse()
    args := flag.Args()

    // Check for correct action
    action := getRequestedAction()

    if flagHelp {
        printUsage()
    } else if action != ACTION_INVALID {
        var peInfo *pe.PEInfo
        var err interface{}

        if len(args) > 0 {
            // Open and parse specified executable
            peFilePath := args[0]
            peInfo, err = pe.OpenExecutable(peFilePath)
            defer peInfo.Close()
            if err != nil {
                // Parse error occurred
                log.Fatal(err)
            }
        } else {
            log.Fatal("File path not specified!")
        }

        // Check for requested action
        if action == ACTION_INFO {
            // Output information
            performInfoOutput(peInfo)
        } else if action == ACTION_DUMP {
            // Dump section
            if len(args) == 3 {
                sectionName := args[1]
                outputFileName := args[2]
                performSectionDump(peInfo, sectionName, outputFileName)
            } else {
                fmt.Println("Wrong arguments number! Expected 3.")
            }
        } else if action == ACTION_EXTRACT {
            // Extract resource
            if len(args) == 3 {
                resourcePath := args[1]
                outputFileName := args[2]
                performResourceExtract(peInfo, resourcePath, outputFileName)
            } else {
                fmt.Println("Wrong arguments number! Expected 3.")
            }
        }
    } else {
        printUsage()
    }
}
