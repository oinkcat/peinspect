package pe

import (
    "os"
    "log"
    "fmt"
    "strings"
    "bytes"
    "encoding/binary"
)

// .exe file DOS header
type DosHeader struct {
    Signature [2]byte
    LastSize uint16
    NBlocks uint16
    NRelocks uint16
    HdrSize uint16
    MinAlloc uint16
    MaxAlloc uint16
    SS uint16
    SP uint16
    Checksum uint16
    IP uint16
    CS uint16
    RelocPos uint16
    NOverlay uint16
    Reserved1 [4]uint16
    OemId uint16
    OemInfo uint16
    Reserved2 [10]uint16
    PEOffset uint32
}

// COFF header
type CoffHeader struct {
    Machine uint16
    NumberOfSections uint16
    TimeDateStamp uint32
    PointerToSymbolTable uint32
    NumberOfSymbols uint32
    SizeOfOptionalHeader uint16
    Characteristics uint16
}

// Read file contents and populate given structure variable
func readIntoStruct(file *os.File, data interface{}) {
    bytesRead := make([]byte, binary.Size(data))
    file.Read(bytesRead)
    
    buffer := bytes.NewBuffer(bytesRead)
    binary.Read(buffer, binary.LittleEndian, data)
}

// Parse internal structures
func parsePE(imgFile *os.File) {
    // Read DOS header
    var dosHeader DosHeader
    readIntoStruct(imgFile, &dosHeader)
    
    // Verify PE signature
    imgFile.Seek(int64(dosHeader.PEOffset), os.SEEK_SET)
    peSignBuf := make([]byte, 4)
    imgFile.Read(peSignBuf)
    
    if strings.Trim(string(peSignBuf), "\000") != "PE" {
        log.Fatal("Invalid PE signature!")
    }
    
    var coffHeader CoffHeader
    readIntoStruct(imgFile, &coffHeader)
    
    fmt.Printf("DOS header: %v\n", dosHeader)
    fmt.Printf("COFF header: %v\n", coffHeader)
}

func Inspect(imgFile *os.File) {
    parsePE(imgFile)
}
