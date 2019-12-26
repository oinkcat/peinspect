package main

import (
	"testing"
	"log"
	"./peformat"
)

const TEST_EXE = "./example/testapp.exe"
const TEST_DLL = "./example/TestLib.dll"
const TEST_ASSEMBLY = "./example/testdotnet.exe"

func TestBasicExecutableInfo(t *testing.T) {
	log.Println("Testing parse of EXE file and retreiving basic info")

	exeInfo, err := pe.OpenExecutable(TEST_EXE)
	defer exeInfo.Close()

	if err == nil {
		if len(exeInfo.Sections) == 0 ||
		   len(exeInfo.Imports) == 0 ||
		   len(exeInfo.Resources) == 0 {
			   t.Error("Failed to read basic information from PE file")
		   }
	} else {
		t.Error(err)
	}
}

func TestDLLExports(t *testing.T) {
	log.Println("Testing parse of DLL and retreiving export table...")

	dllInfo, err := pe.OpenExecutable(TEST_DLL)
	defer dllInfo.Close()

	if err == nil {
		if len(dllInfo.Exports.FunctionNames) == 0 {
			t.Error("Failed to get exported functions list")
		}
	} else {
		t.Error(err)
	}
}

func TestIsDotNet(t *testing.T) {
	log.Println("Testing parse of .NET assembly...")

	netExeInfo, err := pe.OpenExecutable(TEST_ASSEMBLY)
	defer netExeInfo.Close()

	if err == nil {
		if netExeInfo.CLRInfo.Flags == 0 {
			t.Error("Executable is not a .NET assembly")
		}
	} else {
		t.Error(err)
	}
}