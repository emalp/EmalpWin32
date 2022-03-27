#include <stdio.h>
#include <Windows.h>
#include <string.h>
#include "EnvironmentBlocks.h"

int main()
{
    LoadLibrary(L"user32.dll");

    printf("Using my own `GetModuleHandle` and `GetProcAddress`\n");

    HMODULE NTdllbase = Malp_GetModuleHandleW(L"user32.dll");

    //printf("NTDLL base is: %x\n", NTdllbase);

    const char* msgbox = "MessageBoxA";

    FARPROC FunctionAddress = Malp_GetProcAddress(NTdllbase, msgbox);
    if (FunctionAddress == NULL) {
        printf("Function not found.\n");
        exit(1);
    }


    typedef int(__stdcall* MessageTing) (HWND, LPCSTR, LPCSTR, UINT);
    MessageTing MessageFunction = (MessageTing)FunctionAddress;
    (*MessageFunction)(0, "It works! emalp is da best heroo", 0, 0);

    getchar();

}
