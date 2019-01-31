package pe

import (
    "os"
    "log"
    "fmt"
    "strings"
    "bytes"
    "encoding/binary"
)

const (
    // Machine type
    MT_I386 = 0x14c
    MT_X64 = 0x8664
    MT_ARM7 = 0x1c4
    MT_IA64 = 0x200
    MT_EFI = 0xebc
    MT_ARM64 = 0xaa64
    MT_CLI = 0xc0ee
    
    // Characteristics
    CHR_SYSTEM = 0x1000
    CHR_DLL = 0x2000
)

// Parsed information
type PEInfo struct {
    archType uint16
    isDriver bool
    isDLL bool
    entryPointAddress uint32
}

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

// PE optional header common fields
type PEOptHeaderCommon struct {
    Signature uint16
    MajorLinkerVersion byte
    MinorLinkerVersion byte
    SizeOfCode uint32
    SizeOfinitializedData uint32
    SizeOfUninitializedData uint32
    AddressOfEntryPoint uint32
    BaseOfCode uint32
}

// Read file contents and populate given structure variable
func readIntoStruct(file *os.File, data interface{}) {
    bytesRead := make([]byte, binary.Size(data))
    file.Read(bytesRead)
    
    buffer := bytes.NewBuffer(bytesRead)
    binary.Read(buffer, binary.LittleEndian, data)
}

// Parse internal structures
func parsePE(imgFile *os.File) *PEInfo {
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
    
    // COFF header
    var coffHeader CoffHeader
    readIntoStruct(imgFile, &coffHeader)
    
    // PE optional header
    var peOptCommon PEOptHeaderCommon
    readIntoStruct(imgFile, &peOptCommon)
    
    return &PEInfo {
        coffHeader.Machine,
        coffHeader.Characteristics & CHR_SYSTEM != 0,
        coffHeader.Characteristics & CHR_DLL != 0,
        peOptCommon.AddressOfEntryPoint,
    }
}

// Parse PE executable
func ParseFile(imgFile *os.File) *PEInfo {
    return parsePE(imgFile)
}

func (pe *PEInfo) Is64bit() bool {
    return pe.archType == MT_X64 || pe.archType == MT_IA64 || pe.archType == MT_ARM64
}

func (pe *PEInfo) Arch() string {
    knownArchs := map[uint16]string {
        MT_I386: "Intel 386",
        MT_X64: "Intel/AMD x64",
        MT_ARM7: "ARM",
        MT_IA64: "Intel Itanium",
        MT_EFI: "EFI bytecode",
        MT_ARM64: "ARM",
        MT_CLI: "Microsoft CLI MSIL",
    }
    
    arch, ok := knownArchs[pe.archType]
    if ok {
        return arch
    }
    return "Other"
}

// Print basic information
func (pe *PEInfo) Inspect() {
    fmt.Printf("Architecture: %s\n", pe.Arch())
    fmt.Printf("Is 64 bit: %v\n", pe.Is64bit())
    
    if(pe.isDriver) {
        fmt.Println("System image (driver) file")
    }
    
    if(pe.isDLL) {
        fmt.Println("DLL image file")
    }
    
    fmt.Printf("Entry point: %#X\n", pe.entryPointAddress)
}
