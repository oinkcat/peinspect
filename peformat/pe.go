package pe

import (
    "os"
    "io"
    "log"
    "errors"
    "fmt"
    "strings"
    "strconv"
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
    DIR_DEBUG = 6
    DIR_COM_DESCRIPTOR = 14

    // Section characteristics
    SCN_CODE uint32 = 0x20
    SCN_INITIALIZED_DATA uint32 = 0x40
    SCN_UNINITIALIZED_DATA uint32 = 0x80
    SCN_MEM_EXECUTE uint32 = 0x20000000
    SCN_MEM_READ uint32 = 0x40000000
    SCN_MEM_WRITE uint32 = 0x80000000

    // Resource types
    RES_TYPE_ICON = 3
    RES_TYPE_GROUP_ICON = 14

    // CLR header flags
    COMIMAGE_FLAGS_ILONLY = 0x01
    COMIMAGE_FLAGS_32BITREQUIRED = 0x02
    COMIMAGE_FLAGS_IL_LIBRARY = 0x04
    COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x08
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x10
    COMIMAGE_FLAGS_TRACKDEBUGDATA = 0x10000
    COMIMAGE_FLAGS_32BITPREFERRED = 0x20000
)

// Parsed information
type PEInfo struct {
    file *os.File
    // Basic info
    FileName string
    archType uint16
    isDriver bool
    isDLL bool
    isDotNetAssembly bool
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
    Sections []PESectionInfo
    // Function imports
    Imports []PEImportExportInfo
    // Function exports
    Exports PEImportExportInfo
    // Resources
    Resources []PEResource
    // .NET CLR info
    CLRInfo COR20Header
}

// Section information
type PESectionInfo struct {
    Name string
    Size uint32
    characteristics uint32
    virtualAddress uint32
    filePointer int64
}

// Import information
type PEImportExportInfo struct {
    LibraryName string
    FunctionNames []string
}

// Resource information
type PEResource struct {
    Id string
    fileOffset int64
    Size uint32
}

// Legacy DOS header
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

// Export directory header
type ExportDirectory struct {
    Characteristics uint32
    TimeDateStamp uint32
    MajorVersion uint16
    MinorVersion uint16
    Name uint32
    Base uint32
    NumberOfFunctions uint32
    NumberOfNames uint32
    AddressOfFunctions uint32
    AddressOfNames uint32
    AddressOfNameOrdinals uint32
}

// Resource directory
type ResourceDirectory struct {
    Characteristics uint32
    TimeDateStamp uint32
    MajorVersion uint16
    MinorVersion uint16
    NumberOfNamedEntries uint16
    NumberOfIdEntries uint16
}

// Resource directory entry
type ResourceDirectoryEntry struct {
    NameId uint32
    DataPtr uint32
}

// Structure that contains resource data pointer and size
type ResourceDataEntry struct {
    DataPtr uint32
    Size uint32
    CodePage uint32
    Reserved uint32
}

// .ICO file header
type IconHeader struct {
    Width uint8
    Height uint8
    ColorCount uint8
    Reserved uint8
    Planes uint16
    BitCount uint16
    BytesInRes uint32
}

// CLR loader information
type COR20Header struct {
    Size uint32
    MajorRuntimeVersion uint16
    MinorRuntimeVersion uint16
    MetaData DataDirectory
    Flags uint32
    EntryPoint uint32
    Resources DataDirectory
    CodeManagerTable DataDirectory
    VTableFixups DataDirectory
    ExportAddressTablejumps DataDirectory
    ManagedNativeHeader DataDirectory
}

// Parse internal structures
func parsePE(imgFile *os.File) (*PEInfo, error) {
    // Read DOS header
    var dosHeader DosHeader
    readIntoStruct(imgFile, &dosHeader)
    
    // Verify PE signature
    imgFile.Seek(int64(dosHeader.PEOffset), os.SEEK_SET)
    peSignBuf := make([]byte, 4)
    imgFile.Read(peSignBuf)
    
    if strings.Trim(string(peSignBuf), "\000") != "PE" {
        return nil, errors.New("Invalid PE signature!")
    }
    
    // COFF header
    var coffHeader CoffHeader
    readIntoStruct(imgFile, &coffHeader)
    
    // PE optional header
    var peOptCommon PEOptHeaderCommon
    readIntoStruct(imgFile, &peOptCommon)

    peInfo := &PEInfo {
        file: imgFile,
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
        return nil, errors.New("Executable type not supported!")
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
    if _, hasImports := peInfo.directory[DIR_IMPORT]; hasImports {
        parseImports(imgFile, peInfo)
    }

    // Exports
    if _, hasExports := peInfo.directory[DIR_EXPORT]; hasExports {
        parseExports(imgFile, peInfo)
    }

    // Resources
    if _, hasResources := peInfo.directory[DIR_RESOURCE]; hasResources {
        parseResources(imgFile, peInfo)
    }

    // CLR header
    if _, hasClrInfo := peInfo.directory[DIR_COM_DESCRIPTOR]; hasClrInfo {
        parseClrHeader(imgFile, peInfo)
    }
    
    return peInfo, nil
}

// Parse PE file sections
func parsePESections(imgFile *os.File, info *PEInfo) {
    nSections := int(info.numOfSections)
    info.Sections = make([]PESectionInfo, nSections)
    
    for i := 0; i < nSections; i++ {
        var sectHeader SectionHeader
        readIntoStruct(imgFile, &sectHeader)

        newSection := PESectionInfo {
            Name: strings.Trim(string(sectHeader.Name[:]), "\000"),
            Size: sectHeader.SizeOfRawData,
            virtualAddress: sectHeader.VirtualAddress,
            filePointer: int64(sectHeader.PointerToRawData),
            characteristics: sectHeader.Characteristics,
        }

        info.Sections[i] = newSection
    }
}

// Find section that contains given RVA
func (pe *PEInfo) findSectionByRva(rva uint32) *PESectionInfo {
    sectionPtr := &pe.Sections[0]
    for i := 1; i < len(pe.Sections); i++ {
        if(pe.Sections[i].virtualAddress > rva) {
            break
        }
        sectionPtr = &pe.Sections[i]
    }
    return sectionPtr
}

// Get file position corresponding to given RVA
func (section *PESectionInfo) translateRva(rva uint32) uint32 {
    offsetFromStart := rva - section.virtualAddress
    return uint32(section.filePointer) + offsetFromStart
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
    info.Imports = make([]PEImportExportInfo, len(allImportDescriptors))
    for i, descriptor := range(allImportDescriptors) {
        namePos := dataSection.translateRva(descriptor.Name)
        imgFile.Seek(int64(namePos), os.SEEK_SET)
        info.Imports[i] = PEImportExportInfo {
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

// Parse exported functions
func parseExports(imgFile *os.File, info *PEInfo) {
    exportsRva := info.directory[DIR_EXPORT].VirtualAddress
    dataSection := info.findSectionByRva(exportsRva)
    exportsStartPos := dataSection.translateRva(exportsRva)

    imgFile.Seek(int64(exportsStartPos), os.SEEK_SET)
    var exportsHeader ExportDirectory
    readIntoStruct(imgFile, &exportsHeader)

    libNamePos := dataSection.translateRva(exportsHeader.Name)
    imgFile.Seek(int64(libNamePos), os.SEEK_SET)

    numExports := int(exportsHeader.NumberOfNames)
    info.Exports.LibraryName = readAsciiString(imgFile)
    info.Exports.FunctionNames = make([]string, numExports)

    nameRvas := make([]uint32, exportsHeader.NumberOfNames)
    rvaBuf := make([]byte, 4)
    namesStartPos := dataSection.translateRva(exportsHeader.AddressOfNames)
    imgFile.Seek(int64(namesStartPos), os.SEEK_SET)

    // Read all RVAs
    for i := 0; i < numExports; i++ {
        imgFile.Read(rvaBuf)
        nameRvas[i] = binary.LittleEndian.Uint32(rvaBuf)
    }

    // Resolve exported names
    for i, rva := range(nameRvas) {
        funcNamePos := dataSection.translateRva(rva)
        imgFile.Seek(int64(funcNamePos), os.SEEK_SET)
        info.Exports.FunctionNames[i] = readAsciiString(imgFile)
    }
}

// Parse resource section and retreive resource entries
func parseResources(imgFile *os.File, info *PEInfo) {
    const ResDirEntrySize int = 8

    resourcesRva := info.directory[DIR_RESOURCE].VirtualAddress
    resDataSection := info.findSectionByRva(resourcesRva)
    resourceDirPos := resDataSection.translateRva(resourcesRva)

    allResources := []PEResource {}

    // Look for contents of resource directory
    var walkDirectory func(position int64, path string)
    walkDirectory = func(position int64, path string) {
        imgFile.Seek(position, os.SEEK_SET)

        var resDirectory ResourceDirectory
        readIntoStruct(imgFile, &resDirectory)
    
        totalEntriesCount := int(resDirectory.NumberOfNamedEntries +
                                 resDirectory.NumberOfIdEntries)
        
        // Read contents of directory
        entriesStartPos, _ := imgFile.Seek(0, os.SEEK_CUR)

        for i := 0; i < totalEntriesCount; i++ {
            entryPos := int64(i * ResDirEntrySize) + entriesStartPos
            imgFile.Seek(entryPos, os.SEEK_SET)

            var dirEntry ResourceDirectoryEntry
            readIntoStruct(imgFile, &dirEntry)
    
            entryFilePos := (dirEntry.DataPtr & 0x7FFFFFFF) + resourceDirPos
            entryId := dirEntry.NameId & 0x7FFFFFFF

            // Determine entry type
            if dirEntry.DataPtr & 0x80000000 > 0 {
                // Entry is directory - recursively walk through it
                nestedDirPath := fmt.Sprintf("%s%d/", path, entryId)
                walkDirectory(int64(entryFilePos), nestedDirPath)
            } else {
                // Entry is data - append to resulting array
                var dataEntry ResourceDataEntry
                readIntoStruct(imgFile, &dataEntry)
                offset := int64(resDataSection.translateRva(dataEntry.DataPtr))

                resource := PEResource {
                    Id: fmt.Sprintf("%s%d", path, entryId),
                    fileOffset: offset,
                    Size: dataEntry.Size,
                }
                allResources = append(allResources, resource)
            }
        }
    }

    walkDirectory(int64(resourceDirPos), "/")
    info.Resources = allResources
}

// Read CLR loader information
func parseClrHeader(imgFile *os.File, info *PEInfo) {
    clrHeaderRva := info.directory[DIR_COM_DESCRIPTOR].VirtualAddress
    clrDataSection := info.findSectionByRva(clrHeaderRva)
    clrHeaderPos := int64(clrDataSection.translateRva(clrHeaderRva))

    imgFile.Seek(clrHeaderPos, os.SEEK_SET)
    readIntoStruct(imgFile, &info.CLRInfo)
    info.isDotNetAssembly = true
}

// Get string representation of section info
func (section PESectionInfo) String() string {
    charsMap := map[uint32]string {
        SCN_CODE: "code",
        SCN_INITIALIZED_DATA: "initialized data",
        SCN_UNINITIALIZED_DATA: "uninitialized data",
        SCN_MEM_READ: "read",
        SCN_MEM_WRITE: "write",
        SCN_MEM_EXECUTE: "execute",
    }
    charNames := []string {}

    for flag, name := range(charsMap) {
        if section.characteristics & flag != 0 {
            charNames = append(charNames, name)
        }
    }
    charsString := strings.Join(charNames, ", ")

    return fmt.Sprintf("Name: %s, size: %d, [%s]", section.Name, 
                                                   section.Size, 
                                                   charsString)
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

// Open PE executable file
func OpenExecutable(fileName string) (*PEInfo, error) {
    file, err := os.Open(fileName)

    if err == nil {
        parsedInfo, err := parsePE(file)
        parsedInfo.FileName = file.Name()
        return parsedInfo, err
    } else {
        return nil, err
    }
}

// Close underlying file
func (pe *PEInfo) Close() {
    if pe != nil && pe.file != nil {
        pe.file.Close()
    }
}

// Dump section contents to file
func (pe *PEInfo) DumpSection(section PESectionInfo, writer io.Writer) {
    buffer := make([]byte, section.Size)
    pe.file.Seek(section.filePointer, os.SEEK_SET)
    pe.file.Read(buffer)
    writer.Write(buffer)
}

// Dump resource data to file
func (pe *PEInfo) DumpResourceData(resource PEResource, writer io.Writer) {
    // Special handling for ICON resource
    if(strings.HasPrefix(resource.Id, fmt.Sprintf("/%d/", RES_TYPE_ICON))) {
        pe.writeIconHeader(resource, writer)
    }

    buffer := make([]byte, resource.Size)
    pe.file.Seek(resource.fileOffset, os.SEEK_SET)
    pe.file.Read(buffer)
    writer.Write(buffer)
}

// Extract and write icon header
func (pe *PEInfo) writeIconHeader(resource PEResource, writer io.Writer) {
    const IconSignatureSize = 6
    const IconHeaderSize = 12
    const IconInfoSize = IconHeaderSize + 2
    const IconDataOffset = IconSignatureSize + IconHeaderSize + 4

    // Get GROUP_ICON resource
    var groupIconRes PEResource
    groupIconPrefix := fmt.Sprintf("/%d/", RES_TYPE_GROUP_ICON)

    for _, resInfo := range(pe.Resources) {
        if strings.HasPrefix(resInfo.Id, groupIconPrefix) {
            groupIconRes = resInfo
            break
        }
    }

    // GROUP_ICON found - read icon header for given icon
    if groupIconRes.Size != 0 {
        pathParts := strings.Split(resource.Id, "/")
        iconIndex, _ := strconv.Atoi(pathParts[2])

        headerOffset := IconSignatureSize + IconInfoSize * (iconIndex - 1)
        pe.file.Seek(groupIconRes.fileOffset + int64(headerOffset), os.SEEK_SET)

        var iconHeader IconHeader
        readIntoStruct(pe.file, &iconHeader)

        // Write icon signature, header and data offset prior icon data
        writer.Write([]uint8 { 0, 0, 1, 0, 1, 0 })
        binary.Write(writer, binary.LittleEndian, iconHeader)

        offsetBuf := make([]uint8, 4)
        binary.LittleEndian.PutUint32(offsetBuf, IconDataOffset)
        writer.Write(offsetBuf)
    }
}

// Get string representation of CLR info
func (clrInfo COR20Header) String() string {
    return fmt.Sprintf("Flags: 0x%X\n", clrInfo.Flags)
}

// Get string representation of resource
func (resInfo PEResource) String() string {
    return fmt.Sprintf("%s, size: %d bytes", resInfo.Id, resInfo.Size)
}

// Get string representation of module and used functions
func (modInfo PEImportExportInfo) String() string {
    buffer := new(bytes.Buffer)
    buffer.WriteString(fmt.Sprintf("Module %s:\n", modInfo.LibraryName))

    for _, funcName := range(modInfo.FunctionNames) {
        buffer.WriteString(funcName)
        buffer.WriteRune('\n')
    }

    return buffer.String()
}

// Get basic information as string
func (pe PEInfo) String() string {
    buffer := new(bytes.Buffer)

    appendString := func(line string) {
        buffer.WriteString(line)
    }
    appendFmt := func(format string, args ...interface{}) {
        line := fmt.Sprintf(format, args...)
        appendString(line)
    }

    appendFmt("Architecture: %s", pe.ArchName())
    
    if pe.Is64bit() {
        appendString(", 64 bit")
    } else {
        appendString(", 32 bit")
    }
    appendString("\n")
    
    if pe.isDriver {
        appendString("System image (driver) file\n")
    }
    
    if pe.isDLL {
        appendString("DLL image file\n")
    }

    if pe.isDotNetAssembly {
        appendString("Executable is .NET assembly\n")
    }
    
    appendFmt("Base address: %#x\n", pe.baseAddress)
    appendFmt("Entry point: %#x\n", pe.entryPointAddress)
    appendFmt("Subsystem: %s\n", pe.SubsystemName())
    
    appendFmt("Required OS version: %d.%d\n", pe.osMajorVersion, pe.osMinorVersion)
    appendFmt("Required subsystem version: %d.%d\n", pe.ssMajorVersion, pe.ssMinorVersion)
    
    appendFmt("Reserved memory for stack: %d bytes\n", pe.reservedStackBytes)
    appendFmt("Reserved memory for heap: %d bytes\n", pe.reservedHeapBytes)

    if _, ok := pe.directory[DIR_DEBUG]; ok {
        appendString("Debug information available\n")
    }

    return buffer.String()
}
