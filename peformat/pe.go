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
    
    // Signarures
    SGN_HDR32_MAGIC = 0x10b
    SGN_HDR64_MAGIC = 0x20b
    SGN_HDRROM_MAGIC = 0x107
    
    // Subsystem names
    SS_UNKNOWN = 0
    SS_NATIVE = 1
    SS_WINDOWS_GUI = 2
    SS_WINDOWS_CUI = 3
    SS_OS2_CUI = 5
    SS_POSIX_CUI = 7
    SS_WINDOWS_CE = 9
    SS_EFI_APP = 10
    SS_EFI_BOOT_DRIVER = 11
    SS_EFI_RT_DRIVER = 12
    SS_EFI_ROM = 13
    SS_XBOX = 14
    SS_WINDOWS_BOOT = 16

    // Data directory entries
    DIR_EXPORT = 0
    DIR_IMPORT = 1
    DIR_RESOURCE = 2

    // Section characteristics
    SCN_CODE uint32 = 0x20
    SCN_INITIALIZED_DATA uint32 = 0x40
    SCN_UNINITIALIZED_DATA uint32 = 0x80
    SCN_MEM_EXECUTE uint32 = 0x20000000
    SCN_MEM_READ uint32 = 0x40000000
    SCN_MEM_WRITE uint32 = 0x80000000
)

// Parsed information
type PEInfo struct {
    // basic info
    FileName string
    archType uint16
    isDriver bool
    isDLL bool
    entryPointAddress uint32
    subsystem uint16
    peHeaderOffset uint16
    baseAddress uint64
    numOfSections uint16
    // Required versions
    osMajorVersion uint16
    osMinorVersion uint16
    ssMajorVersion uint16
    ssMinorVersion uint16
    // Reserved memory
    reservedStackBytes uint64
    reservedHeapBytes uint64
    // Data directory
    directory map[int]DataDirectory
    // Sections info
    sections []PESectionInfo
    // Function imports
    Imports []PEImportInfo
}

// Section information
type PESectionInfo struct {
    Name string
    Size uint32
    characteristics uint32
    virtualAddress uint32
    filePointer uint32
}

// Import information
type PEImportInfo struct {
    LibraryName string
    FunctionNames []string
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

// PE Optional Header common fields
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

// 32 bit version of PE Optional Header
type PEOptHeader32Bit struct {
    BaseOfData uint32
    ImageBase uint32
    SectionAlignment uint32
    FileAlignment uint32
    MajorOSVersion uint16
    MinorOSVersion uint16
    MajorImageVersion uint16
    MinorImageVersion uint16
    MajorSubsystemVersion uint16
    MinorSubsystemVersion uint16
    Win32VersionValue uint32
    SizeOfImage uint32
    SizeOfHeaders uint32
    Checksum uint32
    Subsystem uint16
    DLLCharacteristics uint16
    SizeOfStackReserve uint32
    SizeOfStackCommit uint32
    SizeOfHeapReserve uint32
    SizeOfHeapCommit uint32
    LoaderFlags uint32
    NumberOfRvaAndSizes uint32
}

// 64 bit version of PE Optional Header
type PEOptHeader64Bit struct {
    ImageBase uint64
    SectionAlignment uint32
    FileAlignment uint32
    MajorOSVersion uint16
    MinorOSVersion uint16
    MajorImageVersion uint16
    MinorImageVersion uint16
    MajorSubsystemVersion uint16
    MinorSubsystemVersion uint16
    Win32VersionValue uint32
    SizeOfImage uint32
    SizeOfHeaders uint32
    Checksum uint32
    Subsystem uint16
    DLLCharacteristics uint16
    SizeOfStackReserve uint64
    SizeOfStackCommit uint64
    SizeOfHeapReserve uint64
    SizeOfHeapCommit uint64
    LoaderFlags uint32
    NumberOfRvaAndSizes uint32
}

// Data directory entry
type DataDirectory struct {
    VirtualAddress uint32
    Size uint32
}

// Section header
type SectionHeader struct {
    Name [8]byte
    Misc uint32
    VirtualAddress uint32
    SizeOfRawData uint32
    PointerToRawData uint32
    PointerToRelocations uint32
    PointerToLinenumbers uint32
    NumberOfRelocations uint16
    NumberOflineNumbers uint16
    Characteristics uint32
}

// Information of module to import from
type ImportDescriptor struct {
    OriginalFirstThunk uint32
    TimeDateStamp uint32
    ForwarderChain uint32
    Name uint32
    FirstThunk uint32
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

    peInfo := &PEInfo {
        archType: coffHeader.Machine,
        isDriver: coffHeader.Characteristics & CHR_SYSTEM != 0,
        isDLL: coffHeader.Characteristics & CHR_DLL != 0,
        entryPointAddress: peOptCommon.AddressOfEntryPoint,
        numOfSections: coffHeader.NumberOfSections,
    }
    
    var nDirEntries uint32
    // Save Optional PE Header position
    currentPos, _ := imgFile.Seek(0, os.SEEK_CUR)
    peInfo.peHeaderOffset = uint16(currentPos)
    
    if peOptCommon.Signature == SGN_HDR32_MAGIC {
        var pe32Header PEOptHeader32Bit
        readIntoStruct(imgFile, &pe32Header)
        peInfo.baseAddress = uint64(pe32Header.ImageBase)
        peInfo.subsystem = pe32Header.Subsystem
        peInfo.osMajorVersion = pe32Header.MajorOSVersion
        peInfo.osMinorVersion = pe32Header.MinorOSVersion
        peInfo.ssMajorVersion = pe32Header.MajorSubsystemVersion
        peInfo.ssMinorVersion = pe32Header.MinorSubsystemVersion
        peInfo.reservedStackBytes = uint64(pe32Header.SizeOfStackReserve)
        peInfo.reservedHeapBytes = uint64(pe32Header.SizeOfHeapReserve)
        nDirEntries = pe32Header.NumberOfRvaAndSizes
    } else if peOptCommon.Signature == SGN_HDR64_MAGIC {
        var pe64Header PEOptHeader64Bit
        readIntoStruct(imgFile, &pe64Header)
        peInfo.baseAddress = pe64Header.ImageBase
        peInfo.subsystem = pe64Header.Subsystem
        peInfo.osMajorVersion = pe64Header.MajorOSVersion
        peInfo.osMinorVersion = pe64Header.MinorOSVersion
        peInfo.ssMajorVersion = pe64Header.MajorSubsystemVersion
        peInfo.ssMinorVersion = pe64Header.MinorSubsystemVersion
        peInfo.reservedStackBytes = pe64Header.SizeOfStackReserve
        peInfo.reservedHeapBytes = pe64Header.SizeOfHeapReserve
        nDirEntries = pe64Header.NumberOfRvaAndSizes
    } else {
        log.Fatal("Executable type not supported!")
    }
    
    // Data directory entries
    peInfo.directory = make(map[int]DataDirectory, nDirEntries)
    
    for i := 0; i < int(nDirEntries); i++ {
        var sectInfo DataDirectory
        readIntoStruct(imgFile, &sectInfo)
        if(sectInfo.VirtualAddress != 0) {
            peInfo.directory[i] = sectInfo
        }
    }
    
    // Sections
    parsePESections(imgFile, peInfo)

    // Imports
    _, importsExists := peInfo.directory[DIR_IMPORT]
    if importsExists {
        parseImports(imgFile, peInfo)
    }
    
    return peInfo
}

// Parse PE file sections
func parsePESections(imgFile *os.File, info *PEInfo) {
    nSections := int(info.numOfSections)
    info.sections = make([]PESectionInfo, nSections)
    
    for i := 0; i < nSections; i++ {
        var sectHeader SectionHeader
        readIntoStruct(imgFile, &sectHeader)

        newSection := PESectionInfo {
            Name: strings.Trim(string(sectHeader.Name[:]), "\000"),
            Size: sectHeader.SizeOfRawData,
            virtualAddress: sectHeader.VirtualAddress,
            filePointer: sectHeader.PointerToRawData,
            characteristics: sectHeader.Characteristics,
        }

        info.sections[i] = newSection
    }
}

// Find section that contains given RVA
func (pe *PEInfo) findSectionByRva(rva uint32) *PESectionInfo {
    sectionPtr := &pe.sections[0]
    for i := 1; i < len(pe.sections); i++ {
        if(pe.sections[i].virtualAddress > rva) {
            break
        }
        sectionPtr = &pe.sections[i]
    }
    return sectionPtr
}

// Get file position corresponding to given RVA
func (section *PESectionInfo) translateRva(rva uint32) uint32 {
    offsetFromStart := rva - section.virtualAddress
    return section.filePointer + offsetFromStart
}

// Read zero terminated string from file
func readAsciiString(file *os.File) string {
    readBuf:= make([]byte, 8)
    strBuf := new(bytes.Buffer)
    
    for {
        n, _ := file.Read(readBuf)
        readBytes := readBuf[:n]
        zeroPos := bytes.IndexByte(readBytes, 0)
        if zeroPos ==-1 {
            strBuf.Write(readBytes)
        } else {
            strBuf.Write(readBytes[:zeroPos])
            break
        }
    }

    return strBuf.String()
}

// Parse function imports
func parseImports(imgFile *os.File, info *PEInfo) {
    importsRva := info.directory[DIR_IMPORT].VirtualAddress
    dataSection := info.findSectionByRva(importsRva)
    importsStartPos := dataSection.translateRva(importsRva)

    allImportDescriptors := []ImportDescriptor {}
    imgFile.Seek(int64(importsStartPos), os.SEEK_SET)

    // Read raw import data
    for {
        var importDescriptor ImportDescriptor
        readIntoStruct(imgFile, &importDescriptor)
        if importDescriptor.FirstThunk == 0 && importDescriptor.Name == 0 {
            break
        }
        allImportDescriptors = append(allImportDescriptors, importDescriptor)
    }

    // Read details by their RVAs
    info.Imports = make([]PEImportInfo, len(allImportDescriptors))
    for i, descriptor := range(allImportDescriptors) {
        namePos := dataSection.translateRva(descriptor.Name)
        imgFile.Seek(int64(namePos), os.SEEK_SET)
        info.Imports[i] = PEImportInfo { 
            LibraryName: readAsciiString(imgFile), 
            FunctionNames: nil,
        }

        funcRvaArrayPos := dataSection.translateRva(descriptor.FirstThunk)
        rvaArray := []uint32 {}
        imgFile.Seek(int64(funcRvaArrayPos), os.SEEK_SET)
        // Read 4 byte RVA to function name
        rvaBuf := make([]byte, 4)
        for {
            imgFile.Read(rvaBuf)
            byNameRva := binary.LittleEndian.Uint32(rvaBuf)
            if byNameRva == 0 {
                break
            }
            rvaArray = append(rvaArray, byNameRva)
        }

        // Read imported function names
        info.Imports[i].FunctionNames = make([]string, len(rvaArray))
        for fnIdx, nameRva := range(rvaArray) {
            namePos := dataSection.translateRva(nameRva) + 2
            imgFile.Seek(int64(namePos), os.SEEK_SET)
            info.Imports[i].FunctionNames[fnIdx] = readAsciiString(imgFile)
        }
    }
}

// Parse PE executable
func ParseFile(imgFile *os.File) *PEInfo {
    parsedInfo := parsePE(imgFile)
    parsedInfo.FileName = imgFile.Name()
    return parsedInfo
}

// Is image a 64 bit
func (pe *PEInfo) Is64bit() bool {
    return pe.archType == MT_X64 || pe.archType == MT_IA64 || pe.archType == MT_ARM64
}

// Get machine architecture name
func (pe *PEInfo) ArchName() string {
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

func (pe *PEInfo) SubsystemName() string {
    knownSubsystems := map[uint16]string {
        SS_UNKNOWN: "Unknown",
        SS_NATIVE: "Native",
        SS_WINDOWS_GUI: "Windows GUI",
        SS_WINDOWS_CUI: "Windows Console",
        SS_OS2_CUI: "OS/2 Console",
        SS_POSIX_CUI: "POSIX Console",
        SS_WINDOWS_CE: "Windows CE",
        SS_EFI_APP: "EFI Application",
        SS_EFI_BOOT_DRIVER: "EFI Boot Driver",
        SS_EFI_RT_DRIVER: "EFI Runtime Driver",
        SS_EFI_ROM: "EFI ROM image",
        SS_XBOX: "XBOX application",
        SS_WINDOWS_BOOT: "Windows Boot Application",
    }
    
    ssName, ok := knownSubsystems[pe.subsystem]
    if !ok {
        log.Fatalf("Unknown subsystem: %#x!\n", pe.subsystem)
    }
    
    return ssName
}

// Print basic information
func (pe *PEInfo) Inspect() {
    fmt.Printf("Architecture: %s", pe.ArchName())
    
    if pe.Is64bit() {
        fmt.Println(", 64 bit")
    } else {
        fmt.Println(", 32 bit")
    }
    
    if pe.isDriver {
        fmt.Println("System image (driver) file")
    }
    
    if pe.isDLL {
        fmt.Println("DLL image file")
    }
    
    fmt.Printf("Base address: %#x\n", pe.baseAddress)
    fmt.Printf("Entry point: %#x\n", pe.entryPointAddress)
    fmt.Printf("Subsystem: %s\n", pe.SubsystemName())
    
    fmt.Printf("Required OS version: %d.%d\n", pe.osMajorVersion, pe.osMinorVersion)
    fmt.Printf("Required subsystem version: %d.%d\n", pe.ssMajorVersion, pe.ssMinorVersion)
    
    fmt.Printf("Reserved memory for stack: %d bytes\n", pe.reservedStackBytes)
    fmt.Printf("Reserved memory for heap: %d bytes\n", pe.reservedHeapBytes)

    fmt.Println("\nSections:")
    for _, sectInfo := range(pe.sections) {
        fmt.Printf("Name: %s, size: %d\n", sectInfo.Name, sectInfo.Size)
    }

    fmt.Println("\nImports:")
    for _, importInfo := range(pe.Imports) {
        fmt.Printf("Library: %s\n", importInfo.LibraryName)
        for _, funcName := range(importInfo.FunctionNames) {
            fmt.Printf("- %s\n", funcName)
        }
    }
}
