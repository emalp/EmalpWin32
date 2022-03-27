#include <stdio.h>
#include <Windows.h>
#include <string.h>
#include "EnvironmentBlocks.h"

PPEB ProcessEBP = NtCurrentTeb()->ProcessEnvironmentBlock;
PPEB_LDR_DATA ProcessLoaderDataP = ProcessEBP->Ldr;
LIST_ENTRY ListOfModules = ProcessLoaderDataP->InMemoryOrderModuleList;
PLIST_ENTRY ListOfModulesP = &ListOfModules;

HMODULE Malp_GetModuleHandleW(const wchar_t* ModuleName) {

    PLIST_ENTRY CurrentEntryP = ListOfModulesP->Flink;

    while (CurrentEntryP != NULL) {
        PLDR_DATA_TABLE_ENTRY CurrentModule = (PLDR_DATA_TABLE_ENTRY)((BYTE*)CurrentEntryP - sizeof(LIST_ENTRY));
        UNICODE_STRING CurrentModuleBaseName = CurrentModule->BaseDllName;

        if (CurrentModule->DllBase == NULL) {
            return NULL;
        }

        if (_wcsicmp((wchar_t*)CurrentModuleBaseName.Buffer, ModuleName) == 0) {
            return (HMODULE)CurrentModule->DllBase;
        }

        CurrentEntryP = CurrentEntryP->Flink;
    }

    return NULL;

}

FARPROC Malp_GetProcAddress(HMODULE hModule, const char* lpProcName) {
    // we need to now get the process address from the export table of the hModule PE file.

    PIMAGE_DOS_HEADER User32DOSHeaderP = (PIMAGE_DOS_HEADER)hModule;
    WORD DOSMagicNumber = '\x4d\x5a';
    if (User32DOSHeaderP->e_magic != DOSMagicNumber) {
        // Not a valid DOS file.
        return NULL;
    }

    // Now get the NT Headers.
    PIMAGE_NT_HEADERS64 User32NTHeadersP = (PIMAGE_NT_HEADERS64)((BYTE*)User32DOSHeaderP + User32DOSHeaderP->e_lfanew);
    // NT Signature
    DWORD NTSignature = '\x50\x45\x00\x00';
    if (User32NTHeadersP->Signature != NTSignature) {
        //printf("Not a valid PE file.\n");
        return NULL;
    }

    // NT Optional Header
    IMAGE_OPTIONAL_HEADER64 NTOptionalHeader = User32NTHeadersP->OptionalHeader;
    PIMAGE_OPTIONAL_HEADER64 NTOptionalHeaderP = &NTOptionalHeader;

    // Export Data Directory
    IMAGE_DATA_DIRECTORY NTDataDirectory_Export = NTOptionalHeaderP->DataDirectory[0];
    PIMAGE_DATA_DIRECTORY NTDataDirectory_ExportP = &NTDataDirectory_Export;

    // The Export Directory
    PIMAGE_EXPORT_DIRECTORY ExportDirectoryP = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)User32DOSHeaderP + NTDataDirectory_ExportP->VirtualAddress);

    // RVA of array of function Names;
    PDWORD AddressOfNamesP = (PDWORD)((BYTE*)User32DOSHeaderP + ExportDirectoryP->AddressOfNames);
    PDWORD AddressOfFunctionsP = (PDWORD)((BYTE*)User32DOSHeaderP + ExportDirectoryP->AddressOfFunctions);
    PWORD AddressOfNameOrdinalsP = (PWORD)((BYTE*)User32DOSHeaderP + ExportDirectoryP->AddressOfNameOrdinals);
    DWORD NumberOfNames = ExportDirectoryP->NumberOfNames;

    int NameCounter = 0;
    char* CurrentName;
    for (NameCounter = 0; NameCounter < NumberOfNames; NameCounter++) {
        CurrentName = (char*)((BYTE*)User32DOSHeaderP + AddressOfNamesP[NameCounter]);

        if (strcmp(CurrentName, lpProcName) == 0) {

            // the current index is to be located in the ordinal now.
            WORD OrdinalNumber = AddressOfNameOrdinalsP[NameCounter];
            PDWORD FunctionAddress = (PDWORD)((BYTE*)User32DOSHeaderP + AddressOfFunctionsP[OrdinalNumber]);

            return (FARPROC)FunctionAddress;

        }

    }

    return NULL;

}