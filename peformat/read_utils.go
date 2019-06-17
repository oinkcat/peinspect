package pe

import (
	"os"
	"bytes"
	"encoding/binary"
)

// Read file contents and populate given structure variable
func readIntoStruct(file *os.File, data interface{}) {
    bytesRead := make([]byte, binary.Size(data))
    file.Read(bytesRead)
    
    buffer := bytes.NewBuffer(bytesRead)
    binary.Read(buffer, binary.LittleEndian, data)
}

// Read zero terminated string from file
func readAsciiString(file *os.File) string {
    readBuf:= make([]byte, 8)
    strBuf := new(bytes.Buffer)
    
    for {
        n, _ := file.Read(readBuf)
        readBytes := readBuf[:n]
        zeroPos := bytes.IndexByte(readBytes, 0)
        if zeroPos == -1 {
            strBuf.Write(readBytes)
        } else {
            strBuf.Write(readBytes[:zeroPos])
            break
        }
    }

    return strBuf.String()
}